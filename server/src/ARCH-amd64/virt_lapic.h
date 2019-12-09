/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <mutex>
#include <tuple>
#include <queue>

#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/util/unique_cap>
#include <l4/sys/vcpu.h>

#include "irq.h"
#include "timer.h"
#include "mem_access.h"
#include "vm_state.h"
#include "pt_walker.h"
#include "ram_ds.h"
#include "msi_controller.h"
#include "msr_device.h"
#include "mem_types.h"
#include "mmio_device.h"
#include "msi.h"
#include "monitor/lapic_cmd_handler.h"
#include "cpu_dev.h"

using L4Re::Rm;

namespace Gic {

class Virt_lapic : public Vdev::Timer, public Ic
{
  struct LAPIC_registers
  {
    l4_uint32_t tpr;
    l4_uint32_t ppr;
    l4_uint32_t ldr; ///< logical destination register
    l4_uint32_t dfr; ///< destination format register not existent in x2APIC
    l4_uint32_t svr; ///< Spurious vector register
    l4_uint32_t isr[8];
    l4_uint32_t tmr[8];
    l4_uint32_t irr[8];
    l4_uint32_t esr;
    l4_uint32_t cmci;
    l4_uint64_t icr;
    l4_uint32_t therm;
    l4_uint32_t perf;
    l4_uint32_t lint[2];
    l4_uint32_t err;
    l4_uint32_t tmr_init;
    l4_uint32_t tmr_cur;
  };

  struct Timer_div
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER_RO(3, 3, upper, raw);
    CXX_BITFIELD_MEMBER_RO(0, 1, lower, raw);

    Timer_div() : raw(0U) {}
    Timer_div(l4_uint32_t val) : raw(val) {}
    Timer_div(Timer_div const &o) : raw(o.raw) {}

    Timer_div &operator = (const Timer_div &) = default;

    unsigned divisor() const
    {
      unsigned shift = lower() + (upper() << 2);

      return shift == 7 ? 1 : 2u << shift;
    }
  };

  struct Timer_reg
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER(17, 18, mode, raw);
    CXX_BITFIELD_MEMBER(16, 16, masked, raw);
    CXX_BITFIELD_MEMBER(12, 12, pending, raw);
    CXX_BITFIELD_MEMBER(0, 7, vector, raw);

    Timer_reg() : raw(0x00010000) {}
    explicit Timer_reg(l4_uint32_t t) : raw(t) {}

    Timer_reg &operator = (l4_uint32_t t) { raw = t; return *this; }

    bool one_shot() const { return !mode(); }
    bool periodic() const { return mode() == 1; }
    bool tsc_deadline() const { return mode() == 2; }
    void disarm() { masked() = 1; }
  };

  enum XAPIC_consts : unsigned
  {
    Xapic_mode_local_apic_id_shift = 24,
    Xapic_mode_logical_apic_id_shift = 24,
    Xapic_dfr_model_mask = 0xfU << 28,

    Apic_base_bsp_processor = 1UL << 8,
    Apic_base_x2_enabled = 1UL << 10,
    Apic_base_enabled = 1U << 11,

    Lapic_version = 0x60010, /// 10 = integrated APIC, 6 = max LVT entries - 1

    X2apic_ldr_logical_apic_id_mask = 0xffff,
    X2apic_ldr_logical_cluster_id_size = 0xffff,
    X2apic_ldr_logical_cluster_id_shift = 16,
  };

public:
  Virt_lapic(unsigned id, l4_addr_t baseaddr);

  void attach_cpu_thread(L4::Cap<L4::Thread> vthread)
  {
    L4Re::chksys(_lapic_irq->bind_thread(vthread, 0),
                 "Attaching local APIC IRQ to vCPU thread");
  }

  // IC interface
  void clear(unsigned irq) override;
  void set(unsigned irq) override;
  // Overload for MSIs
  void set(Vdev::Msix::Data_register_format data);

  void bind_irq_source(unsigned, cxx::Ref_ptr<Irq_source> const &) override;
  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned) const override;

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override;

  // Timer interface
  void tick() override;

  // APIC soft Irq to force VCPU to handle IRQs
  void irq_trigger(l4_uint32_t irq, bool irr = true);

  // vCPU expected interface
  int next_pending_irq();
  bool is_irq_pending();

  // X2APIC MSR interface
  bool read_msr(unsigned msr, l4_uint64_t *value, bool mmio = false) const;
  bool write_msr(unsigned msr, l4_uint64_t value, bool mmio = false);

  l4_addr_t apic_base() const { return _lapic_memory_address; }

  l4_uint32_t logical_apic_id() const
  {
    return _x2apic_enabled ? _regs.ldr
                           : _regs.ldr >> Xapic_mode_logical_apic_id_shift;
  }

  /**
   * Match a destination ID bitmask against this LAPIC's unique logical ID.
   */
  bool match_ldr(l4_uint32_t did) const
  {
    auto logical_id = logical_apic_id();

    if (_x2apic_enabled)
      {
        // x2APIC supports only cluster mode
        // ldr format: 31:16 cluster id, 15:0 logical APIC ID
        // XXX SMP: assumption cluster id = 0 as no SMP support.
        logical_id &= X2apic_ldr_logical_apic_id_mask;
      }
    else
      {
        // Intel SDM: October 2017: cluster modes: flat and hierarchical cluster
        // flat cluster only in p6 and pentium processors;
        // hierarchical cluster need a cluster manager device.
        // => flat address mode is the only supported one.
        // flat address mode: dfr[31:28] = 0b1111;
        if ((_regs.dfr & Xapic_dfr_model_mask) != Xapic_dfr_model_mask)
          {
            trace().printf(
              "Cluster addressing mode not supported; MSI dropped\n");
            return false;
          }
      }

    return logical_id & did;
  }

  l4_uint32_t id() const { return _lapic_x2_id; }
  l4_uint32_t task_prio_class() const { return _regs.tpr & 0xf0; }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "LAPIC"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "LAPIC"); }

  L4Re::Util::Unique_cap<L4::Irq> _lapic_irq; /// IRQ to notify VCPU
  l4_addr_t const _lapic_memory_address;
  l4_uint32_t _lapic_x2_id;
  unsigned _lapic_version;
  std::mutex _int_mutex;
  std::mutex _tmr_mutex;
  LAPIC_registers _regs;
  Timer_reg _timer;
  Timer_div _timer_div;
  l4_uint64_t _tsc_deadline;
  l4_kernel_clock_t _last_ticks_tsc;
  bool _x2apic_enabled;
  unsigned _irq_queued[256];
  cxx::Ref_ptr<Irq_source> _sources[256];
  std::queue<unsigned> _non_irr_irqs;
}; // class Virt_lapic


class Lapic_array
: public Vmm::Mmio_device_t<Lapic_array>,
  public Vdev::Device,
  public Vmm::Msr_device,
  public Monitor::Lapic_cmd_handler<Monitor::Enabled, Lapic_array>
{
  enum
  {
    Max_lapics = Vmm::Cpu_dev::Max_cpus,
    X2apic_msr_base = 0x800,
    Lapic_mem_addr = 0xfee00000,
    Lapic_mem_size = 0x1000,
  };
  static_assert(!(Lapic_mem_addr & 0xfff), "LAPIC memory is 4k-aligned.");

public:
  explicit Lapic_array(unsigned max_phys_addr_bit)
  : _max_phys_addr_mask((1UL << max_phys_addr_bit) - 1)
  {
    assert((Lapic_mem_addr & _max_phys_addr_mask) == Lapic_mem_addr);
  }

  bool send_to_logical_dest_id(l4_uint32_t did,
                               Vdev::Msix::Data_register_format data) const
  {
    bool sent = false;
    for (auto &lapic : _lapics)
      if (lapic && lapic->match_ldr(did))
        {
          lapic->set(data);
          sent = true;
        }

    return sent;
  }

  Vmm::Region mmio_region() const
  {
    return Vmm::Region::ss(Vmm::Guest_addr(Lapic_mem_addr), Lapic_mem_size,
                           Vmm::Region_type::Virtual);
  }

  cxx::Ref_ptr<Virt_lapic> get(unsigned core_no)
  {
    return (core_no < Max_lapics) ? _lapics[core_no] : nullptr;
  }

  Virt_lapic *get_lowest_prio() const
  {
    // init value greater 15, as task priority is between 1 and 15;
    l4_uint32_t prio = 20;
    Virt_lapic *lowest_prio_apic = nullptr;

    for (auto &lapic : _lapics)
      {
        if (!lapic)
          continue;

        auto apic_prio = lapic->task_prio_class();
        if (apic_prio < prio)
          {
            prio = apic_prio;
            lowest_prio_apic = lapic.get();
          }
      }

    return lowest_prio_apic;
  }

  void register_core(unsigned core_no)
  {
    if (_lapics[core_no])
      {
        Dbg().printf("Local APIC for core %u already registered\n", core_no);
        return;
      }

    _lapics[core_no] = Vdev::make_device<Virt_lapic>(core_no, Lapic_mem_addr);
  }

  // Mmio device if
  l4_umword_t read(unsigned reg, char, unsigned cpu_id)
  {
    assert(cpu_id < Max_lapics && _lapics[cpu_id]);

    l4_uint64_t val = -1;
    _lapics[cpu_id]->read_msr(reg2msr(reg), &val, true);

    return val;
  }

  void write(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
  {
    assert(cpu_id < Max_lapics && _lapics[cpu_id]);

    _lapics[cpu_id]->write_msr(reg2msr(reg), value, true);
  }

  // Msr_device interface
  bool read_msr(unsigned msr, l4_uint64_t *value, unsigned vcpu_no) const override
  {
    assert(vcpu_no < Max_lapics && _lapics[vcpu_no]);

    return _lapics[vcpu_no]->read_msr(msr, value);
  };

  bool write_msr(unsigned msr, l4_uint64_t value, unsigned vcpu_no) override
  {
    assert(vcpu_no < Max_lapics && _lapics[vcpu_no]);

    return _lapics[vcpu_no]->write_msr(msr, value);
  }

private:
  static unsigned reg2msr(unsigned reg)
  { return (reg >> 4) | X2apic_msr_base; }

  l4_uint64_t _max_phys_addr_mask;
  cxx::Ref_ptr<Virt_lapic> _lapics[Max_lapics];
}; // class Lapic_array


/**
 * MSI-X control for MSI routing.
 *
 * This class checks if the Redirection Hint is set, then it selects the LAPIC
 * with the lowest interrupt priority as recipient and rewrites the DID field
 * according to the Destination Mode.
 * If RH=0 the MSI is sent to the specified LAPIC(s) according to the DM.
 *
 * Design wise, this class is located between IO-MMU and all LAPICs.
 */
class Msix_control : public Msix_controller, public Vdev::Device
{
public:
  Msix_control(cxx::Ref_ptr<Lapic_array> apics) : _apics(apics) {}

  // Msix_controller interface
  void send(l4_uint64_t msix_addr, l4_uint32_t msix_data) const override
  {
    Vdev::Msix::Interrupt_request_compat addr(msix_addr);
    Vdev::Msix::Data_register_format data(msix_data);

    if (addr.fixed() != Vdev::Msix::Address_interrupt_prefix)
      {
        trace().printf("Interrupt request prefix invalid; MSI dropped.\n");
        return;
      }

    if (addr.redirect_hint())
      {
        // Find LAPIC with lowest TPR and send the MSI its way. We shortcut it
        // here to improve performance. Alternatively, we can rewrite the MSI
        // address to physical destination mode and wirte the local APIC ID to
        // the DID field.
        Virt_lapic *lapic = _apics->get_lowest_prio();

        trace().printf(
          "Lowest interrupt priority arbitration: send to LAPIC 0x%x\n",
          lapic->id());

        lapic->set(data);
        return;
      }

    if (!addr.dest_mode())
      {
        // physical addressing mode:
        //   dest_id() references a local APIC ID
        auto lapic = _apics->get(addr.dest_id()).get();
        if (lapic)
          {
            lapic->set(data);
            return;
          }
      }
    else
      {
        // logical addressing mode:
        //   dest_id() is a bitmask of logical APIC ID targets
        if (_apics->send_to_logical_dest_id(addr.dest_id(), data))
          return;
      }

    info().printf(
      "No valid LAPIC found; MSI dropped. MSI address 0x%llx, data 0x%x\n",
      msix_addr, msix_data);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "MSI-CTLR"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "MSI-CTLR"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "MSI-CTLR"); }

  cxx::Ref_ptr<Lapic_array> _apics;
}; // class Msix_control

/**
 * IO-APIC stub. WIP!
 *
 * TODO The Ic interface is a bit off, as there is no way to clear an IRQ, as
 * the IO-APIC sends an MSI to the MSI-controller when a device sends a legacy
 * IRQ.
 *  set: send an MSI instead of the legacy IRQ (programmed by OS)
 *  clear: nop
 *  bind_irq_source:  ?
 *  get_irq_source: ?
 *  dt_get_interrupt: parse DT
 *
 */
class Io_apic : public Ic, public Vmm::Mmio_device_t<Io_apic>
{
  enum
  {
    Io_apic_mem_size = 0x1000,
    Irq_cells = 1, // keep in sync with virt-pc.dts
  };

public:
  enum
  {
    Mmio_addr = 0xfec00000,
  };

  Io_apic(cxx::Ref_ptr<Lapic_array> apics) : _apics(apics) {}

  // Mmio device interface
  l4_umword_t read(unsigned reg, char, unsigned cpu_id)
  {
    trace().printf("Unimplemented MMIO read to register %d by CPU %d\n", reg,
                  cpu_id);
    return -1;
  }

  void write(unsigned reg, char, l4_umword_t, unsigned cpu_id)
  {
    trace().printf("Unimplemented MMIO write to register %d by CPU %d\n", reg,
                  cpu_id);
  }

  // IC interface
  void set(unsigned irq) override { _apics->get(0)->set(irq); }

  void clear(unsigned irq) override { _apics->get(0)->clear(irq); }

  void bind_irq_source(unsigned irq,
                       cxx::Ref_ptr<Irq_source> const &src) override
  {
    _apics->get(0)->bind_irq_source(irq, src);
  }

  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned irq) const override
  {
    return _apics->get(0)->get_irq_source(irq);
  }

  int dt_get_interrupt(fdt32_t const *prop, int propsz,
                       int *read) const override
  {
    if (propsz < Irq_cells)
      return -L4_ERANGE;

    if (read)
      *read = Irq_cells;

    return fdt32_to_cpu(prop[0]);
  }

  Vmm::Region mmio_region() const
  {
    return Vmm::Region::ss(Vmm::Guest_addr(Mmio_addr), Io_apic_mem_size,
                           Vmm::Region_type::Virtual);
  }


private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "IO-APIC"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "IO-APIC"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "IO-APIC"); }

  cxx::Ref_ptr<Lapic_array> _apics;
}; // class Io_apic

} // namespace Gic
