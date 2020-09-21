/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2020 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
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
#include "msi_arch.h"
#include "monitor/lapic_cmd_handler.h"
#include "cpu_dev.h"
#include "cpu_dev_array.h"

using L4Re::Rm;

namespace Gic {

class Virt_lapic : public Vdev::Timer, public Ic
{
  class Irq_register
  {
    enum : l4_uint8_t
    {
      Reg_no = 256 / sizeof(l4_uint64_t),
      Reg_bits = sizeof(l4_uint64_t) * 8
    };

  public:
    void set_irq(l4_uint8_t irq)
    {
      l4_uint8_t idx = irq / Reg_bits;
      _reg.u64[idx] |= 1ULL << (irq % Reg_bits);
    }

    void clear_irq(l4_uint8_t irq)
    {
      l4_uint8_t idx = irq / Reg_bits;
      _reg.u64[idx] &= ~(1ULL << (irq % Reg_bits));
    }

    int get_highest_irq() const
    {
      for (l4_int8_t i = Reg_no - 1; i >= 0; --i)
        {
          if (!_reg.u64[i])
            continue;

          for (l4_int8_t j = Reg_bits - 1; j >= 0; --j)
            if (_reg.u64[i] & (1ULL << j))
              return i * Reg_bits + j;
        }
      return -1;
    }

    void clear_highest_irq()
    {
      int highest = get_highest_irq();
      if (highest != -1)
        clear_irq(highest);
    }

    bool has_irq() const
    {
      for (auto r: _reg.u64)
        if (r)
          return true;

      return false;
    }

    l4_uint32_t get_reg(l4_uint32_t idx) const
    {
      assert(idx < (256 / sizeof(l4_uint32_t)));
      return _reg.u32[idx];
    }

  private:
    union
    {
      l4_uint64_t u64[Reg_no];
      l4_uint32_t u32[Reg_no * 2];
    } _reg;
  };

  struct LAPIC_registers
  {
    l4_uint32_t tpr;
    l4_uint32_t ppr;
    l4_uint32_t ldr; ///< logical destination register
    l4_uint32_t dfr; ///< destination format register not existent in x2APIC
    l4_uint32_t svr; ///< Spurious vector register
    Irq_register isr;
    Irq_register tmr;
    Irq_register irr;
    l4_uint32_t esr;
    l4_uint32_t cmci;
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
  Virt_lapic(unsigned id);

  void attach_cpu_thread(L4::Cap<L4::Thread> vthread)
  {
    L4Re::chksys(_lapic_irq->bind_thread(vthread, 0),
                 "Attaching local APIC IRQ to vCPU thread");
  }

  // IC interface
  void clear(unsigned) override {}
  void set(unsigned irq) override;
  // Overload for MSIs
  void set(Vdev::Msix::Data_register_format data);

  void bind_eoi_handler(unsigned irq, Eoi_handler *handler) override;
  Eoi_handler *get_eoi_handler(unsigned irq) const override;

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override;

  // Timer interface
  void tick() override;

  // APIC soft Irq to force VCPU to handle IRQs
  void irq_trigger(l4_uint32_t irq, bool irr = true);

  // vCPU expected interface
  int next_pending_irq();
  bool is_irq_pending();

  // X2APIC MSR interface
  bool read_msr(unsigned msr, l4_uint64_t *value) const;
  bool write_msr(unsigned msr, l4_uint64_t value);

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
  Eoi_handler *_sources[256];
  std::queue<unsigned> _non_irr_irqs;
}; // class Virt_lapic


class Lapic_array
: public Vdev::Device,
  public Monitor::Lapic_cmd_handler<Monitor::Enabled, Lapic_array>
{
  enum { Max_lapics = Vmm::Cpu_dev::Max_cpus };

public:
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

  cxx::Ref_ptr<Virt_lapic> get(unsigned core_no) const
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

    _lapics[core_no] = Vdev::make_device<Virt_lapic>(core_no);
  }

private:
  cxx::Ref_ptr<Virt_lapic> _lapics[Vmm::Cpu_dev::Max_cpus];
}; // class Lapic_array

/**
 * Handle Inter-processor interrupts via the Interrupt Command Register (ICR).
 *
 * For details, consult Vol. 3A 10.6.1 of the Intel SDM.
 */
class Icr_handler : public Vdev::Device
{
  enum : l4_uint32_t
  {
    Icr_startup = 0x6,
    Icr_startup_page_shift = 12
  };

  struct Icr
  {
    l4_uint64_t raw;
    CXX_BITFIELD_MEMBER_RO(56, 63, dest_field_mmio, raw);
    CXX_BITFIELD_MEMBER_RO(32, 63, dest_field_x2apic, raw);
    CXX_BITFIELD_MEMBER_RO(20, 31, reserved3, raw);
    CXX_BITFIELD_MEMBER_RO(18, 19, dest_shorthand, raw);
    CXX_BITFIELD_MEMBER_RO(16, 17, reserved2, raw);
    CXX_BITFIELD_MEMBER_RO(15, 15, trigger_mode, raw);
    CXX_BITFIELD_MEMBER_RO(14, 14, trigger_level, raw);
    CXX_BITFIELD_MEMBER_RO(13, 13, reserved1, raw);
    CXX_BITFIELD_MEMBER_RO(12, 12, delivery_status, raw);
    CXX_BITFIELD_MEMBER_RO(11, 11, dest_mode, raw);
    CXX_BITFIELD_MEMBER_RO(8, 10, delivery_mode, raw);
    CXX_BITFIELD_MEMBER_RO(0, 7, vector, raw);
    CXX_BITFIELD_MEMBER_RO(0, 31, lower, raw);

    Icr() : raw(0U) {}
    Icr(uint64_t val) : raw(val) {}
  };

  enum Destination_shorthand
  {
    No_shorthand = 0,
    Self = 1,
    All_including_self = 2,
    All_excluding_self = 3
  };

public:
  enum : unsigned
  {
    Icr_msr = 0x830,
    Icr_mmio_ext = 0x831
  };

  bool read(unsigned msr, l4_uint64_t *value, unsigned vcpu_no) const
  {
    assert(vcpu_no < Vmm::Cpu_dev::Max_cpus);

    switch (msr)
      {
      case Icr_msr:
        *value = _icr[vcpu_no];
        return true;
      case Icr_mmio_ext:
        *value = _icr[vcpu_no] >> 32;
        return true;
      default:
        return false;
      }
  }

  bool write(unsigned msr, l4_uint64_t value, unsigned vcpu_no, bool mmio)
  {
    assert(vcpu_no < Vmm::Cpu_dev::Max_cpus);

    switch (msr)
      {
      case Icr_msr:
        // If the write originates from an MMIO access, only the lower 32bit of
        // the ICR should be written.
        if (mmio)
          _icr[vcpu_no] =
            (_icr[vcpu_no] & 0xffffffff00000000UL) | (value & 0xffffffffU);
        else
          _icr[vcpu_no] = value;
        // Vol. 3A 10.6.1: "The act of writing to the low doubleword of the ICR
        // causes the IPI to be sent."
        send_ipi(_icr[vcpu_no], vcpu_no, !mmio);
        return true;
      case Icr_mmio_ext:
        _icr[vcpu_no] = (_icr[vcpu_no] & 0xffffffffU) | (value << 32);
        return true;
      default:
        return false;
      }
  }

  /**
   * Register the CPU device array with the IPI handler.
   *
   * \param cpus  Pointer to the CPU container.
   */
  void register_cpus(cxx::Ref_ptr<Vmm::Cpu_dev_array> const &cpus)
  { _cpus = cpus; }

  /**
   * Register the MSI-X Controller with the IPI handler.
   *
   * \param msix_ctrl  Pointer to the MSI-X Controller.
   */
  void register_msix_ctrl(cxx::Ref_ptr<Msix_controller> const &msix_ctrl)
  { _msix_ctrl = msix_ctrl; }

private:
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "IPI"); }

  enum : l4_uint32_t { Data_register_format_mask = 0x0000c7ffU };

  /**
   * Send an Inter-Processor Interrupt message.
   *
   * This function handles the INIT-SIPI-SIPI sequence (cf. Vol. 3A 8.4.3 of
   * the Intel 64 and IA-32 Architectures Software Developer's Manual) and
   * forwards all other IPIs to the MSI-X Controller for distribution.
   *
   * \param icr_reg  Content of the ICR register.
   * \param vcpu_no  Current vCPU ID.
   * \param x2apic   Indicate if X2APIC mode is in use.
   */
  void send_ipi(l4_uint64_t icr_reg, unsigned vcpu_no, bool x2apic) const
  {
    Icr icr(icr_reg);

    using namespace Vdev::Msix;

    // cf. ICR format: Vol. 3A 10.6.1 / Figure 10-12 vs.
    // the MSI data format: Vol. 3A 10.11.2 / Figure 10-25
    Data_register_format const data(icr.lower() & Data_register_format_mask);

    // Cf. Vol 3A 10.6.1 / Figure 10-12 vs. Vol 3A 10.12.9 / Figure 10-28
    l4_uint32_t id = x2apic ? icr.dest_field_x2apic() : icr.dest_field_mmio();
    unsigned const max_cpuid = _cpus->max_cpuid();

    // According to Tables 10-3, and 10-4, the Start-Up Delivery Mode is only
    // valid without Destination Shorthand. Whilst the validity of INIT varies
    // across generations, we assume that no shorthand is used for the whole
    // sequence.
    // Because according to Vol. 3A 10.4.7.1 the LDR is set to 0 in
    // wait-for-SIPI state, we require Physical Destination Mode.
    if ((icr.dest_shorthand() == 0) && !icr.dest_mode())
      {
        assert(_cpus != nullptr);

        assert(id <= max_cpuid);

        auto cpu = _cpus->cpu(id);

        if (data.delivery_mode() == Delivery_mode::Dm_init)
          {
            if (data.trigger_level())
              cpu->set_cpu_state(Vmm::Cpu_dev::Cpu_state::Init);
            else
              cpu->set_cpu_state(Vmm::Cpu_dev::Cpu_state::Init_level_de_assert);

            return;
          }
        else if (data.delivery_mode() == Icr_startup)
          {
            if (cpu->get_cpu_state()
                == Vmm::Cpu_dev::Cpu_state::Init_level_de_assert)
              {
                l4_addr_t start_eip = data.vector() << Icr_startup_page_shift;
                start_cpu(id, start_eip);
                cpu->set_cpu_state(Vmm::Cpu_dev::Cpu_state::Startup);
              }
            else
                cpu->set_cpu_state(Vmm::Cpu_dev::Cpu_state::Running);

            return;
          }
      }

    Interrupt_request_compat addr(0ULL);
    addr.fixed() = Address_interrupt_prefix;
    addr.dest_mode() = icr.dest_mode();

    assert(_msix_ctrl != nullptr);

    switch (icr.dest_shorthand())
      {
      case Destination_shorthand::No_shorthand:
        addr.dest_id() = id & 0xffU;
        addr.dest_id_upper() = x2apic ? id >> 8 : 0U;
        _msix_ctrl->send(addr.raw, data.raw);
        break;
      case Destination_shorthand::Self:
        addr.dest_id() = vcpu_no & 0xffU;
        addr.dest_id_upper() = x2apic ? vcpu_no >> 8 : 0U;
        _msix_ctrl->send(addr.raw, data.raw);
        break;
      case Destination_shorthand::All_including_self:
        for (unsigned i = 0; i <= max_cpuid; ++i)
          {
            addr.dest_id() = i & 0xffU;
            addr.dest_id_upper() = x2apic ? i >> 8 : 0U;
            _msix_ctrl->send(addr.raw, data.raw);
          }
        break;
      case Destination_shorthand::All_excluding_self:
        for (unsigned i = 0; i <= max_cpuid; ++i)
          {
            if (i == vcpu_no)
              continue;
            addr.dest_id() = i & 0xffU;
            addr.dest_id_upper() = x2apic ? i >> 8 : 0U;
            _msix_ctrl->send(addr.raw, data.raw);
          }
      }
  }

  /**
   * Start an Application Processor.
   *
   * \param id     Number of the CPU to be started.
   * \param entry  Real Mode entry address.
   */
  void start_cpu(unsigned id, l4_addr_t entry) const
  {
    auto vcpu = _cpus->cpu(id)->vcpu();
    vcpu->r.sp = 0;
    vcpu->r.ip = entry;
    info().printf("Starting CPU %u on EIP 0x%lx\n", id, entry);
    _cpus->cpu(id)->reschedule();
  }

  l4_uint64_t _icr[Vmm::Cpu_dev::Max_cpus] = { 0, };
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
  cxx::Ref_ptr<Msix_controller> _msix_ctrl;
}; // class Icr_handler

class Lapic_access_handler
: public Vmm::Mmio_device_t<Lapic_access_handler>,
  public Vmm::Msr_device,
  public Vdev::Device
{
  enum
  {
    X2apic_msr_base = 0x800,
    Lapic_mem_size = 0x1000,
  };

public:
  enum { Mmio_addr = 0xfee00000 };
  static_assert(!(Mmio_addr & 0xfff), "LAPIC memory is 4k-aligned.");

  Lapic_access_handler(cxx::Ref_ptr<Lapic_array> apics,
                       cxx::Ref_ptr<Icr_handler> icr_handler,
                       unsigned max_phys_addr_bit)
  : _max_phys_addr_mask((1UL << max_phys_addr_bit) - 1),
    _apics(apics),
    _icr_handler(icr_handler)
  {
    assert((Mmio_addr & _max_phys_addr_mask) == Mmio_addr);
  }

  // Msr device interface
  bool read_msr(unsigned msr, l4_uint64_t *value,
                unsigned vcpu_no) const override
  {
    if (msr == Icr_handler::Icr_msr || msr == Icr_handler::Icr_mmio_ext)
      return _icr_handler->read(msr, value, vcpu_no);

    auto lapic = _apics->get(vcpu_no);

    assert((lapic != nullptr) && "Local APIC found at vcpu_no.");

    return lapic->read_msr(msr, value);
  };

  bool write_msr(unsigned msr, l4_uint64_t value, unsigned vcpu_no) override
  {
    return dispatch_msr(msr, value, vcpu_no, false);
  }

  // Mmio device interface
  l4_umword_t read(unsigned reg, char, unsigned cpu_id) const
  {
    l4_uint64_t val = -1;
    read_msr(reg2msr(reg), &val, cpu_id);
    return val;
  }

  void write(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
  {
    dispatch_msr(reg2msr(reg), value, cpu_id, true);
  }


  Vmm::Region mmio_region() const
  {
    return Vmm::Region::ss(Vmm::Guest_addr(Mmio_addr), Lapic_mem_size,
                           Vmm::Region_type::Virtual);
  }

private:
  /**
   * Forward an MSR-encoded write to the ICR handler or to a local APIC.
   *
   * \param msr      Number of the MSR written.
   * \param value    Value written.
   * \param vcpu_no  vCPU that the write originates from.
   * \param mmio     Indicates if the write originates from an MMIO write that
   *                 was converted to a MSR write.
   *
   * \return  True if the write was handled successfully, false otherwise.
   */
  bool dispatch_msr(unsigned msr, l4_uint64_t value, unsigned vcpu_no,
                    bool mmio)
  {
    if (msr == Icr_handler::Icr_msr || msr == Icr_handler::Icr_mmio_ext)
      return _icr_handler->write(msr, value, vcpu_no, mmio);

    auto lapic = _apics->get(vcpu_no);

    assert((lapic != nullptr) && "Local APIC found at vcpu_no.");

    return lapic->write_msr(msr, value);
  }

  static unsigned reg2msr(unsigned reg)
  { return (reg >> 4) | X2apic_msr_base; }

  l4_uint64_t _max_phys_addr_mask;
  cxx::Ref_ptr<Lapic_array> _apics;
  cxx::Ref_ptr<Icr_handler> _icr_handler;
}; // class Lapic_access_handler

/**
 * MSI-X control for MSI routing.
 *
 * This class checks if the Redirection Hint is set, then it selects the LAPIC
 * with the lowest interrupt priority as recipient and rewrites the DID field
 * according to the Destination Mode.
 * If RH=0 the MSI is sent to the specified LAPIC(s) according to the DM.
 *
 * Design wise, this class is located between IOMMU and all LAPICs.
 */
class Msix_control : public Msix_controller, public Vdev::Device
{
public:
  Msix_control(cxx::Ref_ptr<Lapic_array> apics) : _apics(apics) {}

  // Msix_controller interface
  void send(l4_uint64_t msix_addr, l4_uint64_t msix_data) const override
  {
    Vdev::Msix::Interrupt_request_compat addr(msix_addr);
    Vdev::Msix::Data_register_format data(msix_data);

    // Always use the extended MSI-X format. If not in use, the upper bits will
    // simply be 0. cf.  Intel Virtualization Technology for Directed I/O
    // Architecture Specification (June 2019) 5.1.8
    l4_uint32_t id = addr.dest_id_upper() | addr.dest_id();

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
        // physical addressing mode: id references a local APIC ID
        auto lapic = _apics->get(id).get();
        if (lapic)
          {
            lapic->set(data);
            return;
          }
      }
    else
      {
        // logical addressing mode: id is a bitmask of logical APIC ID targets
        if (_apics->send_to_logical_dest_id(id, data))
          return;
      }

    info().printf(
      "No valid LAPIC found; MSI dropped. MSI address 0x%llx, data 0x%llx\n",
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
 *  bind_eoi_handler:  ?
 *  get_eoi_handler: ?
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

  void bind_eoi_handler(unsigned irq, Eoi_handler *handler) override
  { _apics->get(0)->bind_eoi_handler(irq, handler); }

  Eoi_handler *get_eoi_handler(unsigned irq) const override
  { return _apics->get(0)->get_eoi_handler(irq); }

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
