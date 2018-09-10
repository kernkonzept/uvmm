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
#include "msi_distributor.h"

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
    l4_uint32_t timer;
    l4_uint32_t therm;
    l4_uint32_t perf;
    l4_uint32_t lint[2];
    l4_uint32_t err;
    l4_uint32_t tmr_init;
    l4_uint32_t tmr_cur;
    l4_uint32_t tmr_div;
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
  void set(unsigned irq) override;
  void clear(unsigned irq) override;

  void bind_irq_source(unsigned, cxx::Ref_ptr<Irq_source> const &) override;
  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned) const override;

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override;

  // Timer interface
  void tick() override;

  // APIC soft Irq to force VCPU to handle IRQs
  void irq_trigger(l4_uint32_t irq);

  // vCPU expected interface
  int next_pending_irq();
  bool is_irq_pending();

  // X2APIC MSR interface
  bool read_msr(unsigned msr, l4_uint64_t *value) const;
  bool write_msr(unsigned msr, l4_uint64_t value);

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

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "LAPIC"); }

  L4Re::Util::Unique_cap<L4::Irq> _lapic_irq; /// IRQ to notify VCPU
  l4_addr_t const _lapic_memory_address;
  l4_uint32_t _lapic_x2_id;
  unsigned _lapic_version;
  std::mutex _int_mutex;
  std::mutex _tmr_mutex;
  LAPIC_registers _regs;
  l4_uint64_t _tsc_deadline;
  bool _x2apic_enabled;
  unsigned _irq_queued[256];
  cxx::Ref_ptr<Irq_source> _sources[256];
}; // class Virt_lapic


#include "mmio_device.h"

class Lapic_array : public Vmm::Mmio_device_t<Lapic_array>, public Vdev::Device
{
  enum
  {
    // XXX sync with Max_cpus
    Max_cores = 1,
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

  Virt_lapic *get_by_dest_id(l4_uint32_t did) const
  {
    for (auto &lapic : _lapics)
      if (lapic && lapic->match_ldr(did))
        return lapic.get();

    return nullptr;
  }

  Vmm::Region mmio_region() const
  { return Vmm::Region::ss(Vmm::Guest_addr(Lapic_mem_addr), Lapic_mem_size); }

  cxx::Ref_ptr<Virt_lapic> get(unsigned core_no)
  {
    return (core_no < Max_cores) ? _lapics[core_no] : nullptr;
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
    assert(cpu_id < Max_cores && _lapics[cpu_id]);

    l4_uint64_t val = -1;
    _lapics[cpu_id]->read_msr(reg2msr(reg), &val);

    return val;
  }

  void write(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
  {
    assert(cpu_id < Max_cores && _lapics[cpu_id]);

    _lapics[cpu_id]->write_msr(reg2msr(reg), value);
  }

private:
  static unsigned reg2msr(unsigned reg)
  { return (reg >> 4) | X2apic_msr_base; }

  l4_uint64_t _max_phys_addr_mask;
  cxx::Ref_ptr<Virt_lapic> _lapics[Max_cores];
}; // class Lapic_array


/**
 * IO-APIC representation for IRQ/MSI routing. WIP!
 */
class Io_apic : public Ic, public Msi_distributor
{
  enum
  {
    Msi_address_interrupt_prefix = 0xfee,

    Irq_cells = 1,// keep in sync with virt-pc.dts
  };

  struct Interrupt_request_compat
  {
    // Interrupt request compatibility format
    l4_uint64_t raw;
    CXX_BITFIELD_MEMBER_RO(32, 63, reserved0_2, raw);
    CXX_BITFIELD_MEMBER_RO(20, 31, fixed, raw);
    CXX_BITFIELD_MEMBER_RO(12, 19, dest_id, raw);
    CXX_BITFIELD_MEMBER_RO(4, 11, reserved0_1, raw);
    CXX_BITFIELD_MEMBER_RO(3, 3, redirect_hint, raw);
    CXX_BITFIELD_MEMBER_RO(2, 2, dest_mode, raw);
    CXX_BITFIELD_MEMBER_RO(0, 1, reserved_0, raw);

    explicit Interrupt_request_compat(l4_uint64_t addr) : raw(addr) {};
    bool is_phys_addr_mode() { return redirect_hint() && !dest_mode(); }
    bool is_logical_addr_mode() { return redirect_hint() && dest_mode(); }
    bool is_direct_addr_mode() { return !redirect_hint(); }
  };

  struct Msi_data_register_format
  {
    // Intel SDM Vol. 3A 10-35, October 2017
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER_RO(15, 15, trigger_mode, raw);
    CXX_BITFIELD_MEMBER_RO(14, 14, trigger_level, raw);
    CXX_BITFIELD_MEMBER_RO( 8, 10, delivery_mode, raw);
    CXX_BITFIELD_MEMBER_RO( 0,  7, vector, raw);

    explicit Msi_data_register_format(l4_uint32_t data) : raw(data) {};
  };

public:
  Io_apic(cxx::Ref_ptr<Lapic_array> apics) : _apics(apics) {}

  // IC interface
  void set(unsigned irq) override
  { _apics->get(0)->set(irq); }

  void clear(unsigned irq) override
  { _apics->get(0)->clear(irq); }

  void bind_irq_source(unsigned irq, cxx::Ref_ptr<Irq_source> const &src) override
  { _apics->get(0)->bind_irq_source(irq, src); }

  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned irq) const override
  { return _apics->get(0)->get_irq_source(irq); }

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override
  {
    if (propsz < Irq_cells)
      return -L4_ERANGE;

    if (read)
      *read = Irq_cells;

    return fdt32_to_cpu(prop[0]);
  }

  // Msi_distributor interface
  void send(Vdev::Msi_msg message) const override
  {
    Interrupt_request_compat addr(message.addr);
    if (addr.fixed() != Msi_address_interrupt_prefix)
      {
        trace().printf("Interrupt request prefix invalid; MSI dropped.\n");
        return;
      }

    Virt_lapic *lapic = nullptr;

    if (addr.is_direct_addr_mode())
      {
        // Direct addressing mode: destination ID references a local APIC ID.
        unsigned did = addr.dest_id();
        lapic = _apics->get(did).get();
      }
    else if (addr.is_phys_addr_mode())
      {
        // physical addressing mode:
        //   dest_id() references a local APIC ID
        lapic = _apics->get(addr.dest_id()).get();
      }
    else
      {
        // logical addressing mode:
        //   dest_id() is a bitmask of logical APIC ID targets
        lapic = _apics->get_by_dest_id(addr.dest_id());
      }

    if (lapic)
      {
        Msi_data_register_format data(message.data);
        lapic->set(data.vector());
      }
    else
      trace().printf("No valid LAPIC found; MSI dropped. MSI address 0x%llx\n",
                     message.addr);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "IO-APIC"); }

  cxx::Ref_ptr<Lapic_array> _apics;
}; // class Io_apic

} // namespace Gic
