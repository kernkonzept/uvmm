/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 */
#pragma once

#include <atomic>
#include <mutex>
#include <tuple>
#include <vector>
#include <queue>

#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/util/unique_cap>
#include <l4/sys/vcpu.h>
#include <l4/util/rdtsc.h>

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
#include "msix.h"
#include "msi_arch.h"
#include "monitor/lapic_cmd_handler.h"
#include "cpu_dev.h"
#include "cpu_dev_array.h"

using L4Re::Rm;

namespace Gic {

class Apic_timer;

class Virt_lapic : public Ic
{
  // These MSRs correspond to the xAPIC MMIO registers.
  // see reg2msr for reference
  enum : l4_uint32_t
  {
    Msr_ia32_apic_base = 0x1b,
    Msr_ia32_tsc_deadline = 0x6e0,
    Msr_ia32_x2apic_apicid = 0x802,
    Msr_ia32_x2apic_version = 0x803,
    Msr_ia32_x2apic_tpr = 0x808,
    Msr_ia32_x2apic_ppr = 0x80a,
    Msr_ia32_x2apic_eoi = 0x80b,
    Msr_ia32_x2apic_ldr = 0x80d,
    // This is only available in xapic mode
    // It is documented in the intel manual chapter 10.6.2.2
    Mmio_apic_destination_format_register = 0x80e,
    Msr_ia32_x2apic_sivr = 0x80f,
    Msr_ia32_x2apic_isr7 = 0x817,
    Msr_ia32_x2apic_tmr7 = 0x81f,
    Msr_ia32_x2apic_irr7 = 0x827,
    Msr_ia32_x2apic_esr = 0x828,
    Msr_ia32_x2apic_lvt_cmci = 0x82f,
    Msr_ia32_x2apic_lvt_timer = 0x832,
    Msr_ia32_x2apic_lvt_thermal = 0x833,
    Msr_ia32_x2apic_lvt_pmi = 0x834,
    Msr_ia32_x2apic_lvt_lint0 = 0x835,
    Msr_ia32_x2apic_lvt_lint1 = 0x836,
    Msr_ia32_x2apic_lvt_error = 0x837,
    Msr_ia32_x2apic_init_count = 0x838,
    Msr_ia32_x2apic_cur_count = 0x839,
    Msr_ia32_x2apic_div_conf = 0x83e,
    Msr_ia32_x2apic_self_ipi = 0x83f,
  };

  class Irq_register
  {
    enum : l4_uint8_t
    {
      Reg_no = 256 / sizeof(l4_uint64_t),
      Reg_bits = sizeof(l4_uint64_t) * 8
    };

  public:
    /**
     * Returns true, if IRQ was set before.
     */
    bool set_irq(l4_uint8_t irq)
    {
      l4_uint8_t idx = irq / Reg_bits;
      l4_uint64_t bit = 1ULL << (irq % Reg_bits);
      bool already_set = _reg.u64[idx] & bit;
      _reg.u64[idx] |= bit;
      return already_set;
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

    void clear()
    {
      memset(_reg.u64, 0, sizeof(l4_uint64_t) * Reg_no);
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

  enum XAPIC_consts : unsigned
  {
    Xapic_mode_local_apic_id_shift = 24,
    Xapic_mode_logical_apic_id_shift = 24,
    Xapic_dfr_model_shift = 28,
    Xapic_dfr_flat_model = 0x0fU,
    Xapic_dfr_cluster_model = 0x00U,

    Apic_base_bsp_processor = 1UL << 8,
    Apic_base_x2_enabled = 1UL << 10,
    Apic_base_enabled = 1U << 11,

    Lapic_version = 0x60014, /// 14 = xAPIC, 6 = max LVT entries - 1

    X2apic_ldr_logical_apic_id_mask = 0xffff,
    X2apic_ldr_logical_cluster_id_shift = 16,
  };

public:
  Virt_lapic(unsigned id, cxx::Ref_ptr<Vmm::Cpu_dev> cpu);

  void attach_cpu_thread(L4::Cap<L4::Thread> vthread)
  {
    L4Re::chksys(_lapic_irq->bind_thread(vthread, 0),
                 "Attaching local APIC IRQ to vCPU thread");
  }

  /**
   * Clear all APIC irqs. This shall be used when entering INIT state.
   */
  void clear_irq_state()
  {
    std::lock_guard<std::mutex> lock(_int_mutex);

    _regs.irr.clear();
    _regs.tmr.clear();
    _regs.isr.clear();
  }

  // IC interface
  void clear(unsigned) override {}

  void set(unsigned irq) override;
  // Overload for MSIs
  void set(Vdev::Msix::Data_register_format data);

  void bind_irq_src_handler(unsigned irq, Irq_src_handler *handler) override;
  Irq_src_handler *get_irq_src_handler(unsigned irq) const override;

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override;

  // APIC soft Irq to force VCPU to handle IRQs
  void irq_trigger(l4_uint32_t irq, bool irr = true);
  void nmi();

  // vCPU expected interface
  bool is_nmi_pending();
  int next_pending_irq();
  bool is_irq_pending();
  bool next_pending_nmi();

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
    l4_uint32_t logical_id = logical_apic_id();

    if (_x2apic_enabled)
      {
        // x2APIC supports only cluster mode
        // [31:16] cluster ID, [15:0] Sub-ID-bitmap
        l4_uint32_t did_cluster = did >> X2apic_ldr_logical_cluster_id_shift;
        l4_uint32_t lid_cluster =
          logical_id >> X2apic_ldr_logical_cluster_id_shift;
        return (did_cluster == lid_cluster)
               && (logical_id & did & X2apic_ldr_logical_apic_id_mask);
      }
    else
      {
        switch (_regs.dfr >> Xapic_dfr_model_shift)
          {
          case Xapic_dfr_flat_model:
            // flat address mode: dfr[31:28] = 0b1111;
            return logical_id & did;
          case Xapic_dfr_cluster_model:
            // cluster addressing mode:
            // DID & logical APIC ID: [7:4]: Cluster, [3:0]: Sub-ID-bitmap
            return (logical_id & 0xf0) == (did & 0xf0)
                   && (logical_id & did & 0xf);
          default:
            return false;
          }
      }
  }

  l4_uint32_t id() const { return _lapic_x2_id; }
  l4_uint32_t task_prio_class() const { return _regs.tpr & 0xf0; }

  cxx::Ref_ptr<Apic_timer> timer()
  { return _apic_timer; }

  bool x2apic_mode() const { return _x2apic_enabled; }

  Vcpu_obj_registry *registry() const { return _registry; }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "LAPIC"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "LAPIC"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "LAPIC"); }

  /// An incoming INIT IPI will place the CPU in INIT mode.
  void init_ipi();

  /**
   * Handle STARTUP IPIs
   *
   * Intel specifies that the correct sequence is INIT, STARTUP, STARTUP.
   * So we make sure to only act on the second STARTUP IPI.
   */
  void startup_ipi(Vdev::Msix::Data_register_format data);

  /**
   * Start an Application Processor.
   *
   * \param entry  Real Mode entry address.
   */
  void start_cpu(l4_addr_t entry);

  cxx::Ref_ptr<Apic_timer> _apic_timer;
  L4Re::Util::Unique_cap<L4::Irq> _lapic_irq; /// IRQ to notify VCPU
  l4_uint32_t _lapic_x2_id;
  unsigned _lapic_version;
  std::mutex _int_mutex;
  LAPIC_registers _regs;
  bool _x2apic_enabled;
  std::atomic<bool> _nmi_pending;
  Irq_src_handler *_sources[256] = {};
  std::queue<unsigned> _non_irr_irqs;
  cxx::Ref_ptr<Vmm::Cpu_dev> _cpu;
  Vcpu_obj_registry * const _registry;
  unsigned _sipi_cnt = 0;
}; // class Virt_lapic


class Lapic_array
: public Vdev::Device,
  public Monitor::Lapic_cmd_handler<Monitor::Enabled, Lapic_array>
{
public:
  /**
   * Process MSI data and destination ID in physical addressing mode.
   *
   * \param did   Destination ID as defined in the MSI/-X address.
   * \param data  MSI/-X data value.
   *
   * \return The destination vCPU IPC registry or nullptr.
   *
   * \pre MSI addressing format is physical.
   */
  Vcpu_obj_registry *physical_mode(l4_uint32_t did,
                                   Vdev::Msix::Data_register_format data)
  {
    if (handle_broadcast(did, data))
      return nullptr;

    auto lapic = get(did);
    if (lapic)
      lapic->set(data);
    else
      info().printf("No LAPIC for DID 0x%x with physical addressing. Data "
                    "0x%llx\n",
                    did, data.raw);

    return lapic ? lapic->registry() : nullptr;
  }

  /**
   * Process MSI data and destination ID in logical addressing mode.
   *
   * \param did   Destination ID as defined in the MSI/-X address.
   * \param data  MSI/-X data value.
   * \param lp    MSI requests lowest priority arbitration.
   *
   * \return The destination vCPU IPC registry or nullptr.
   *
   * \pre MSI addressing format is logical.
   */
  Vcpu_obj_registry *logical_mode(l4_uint32_t did,
                                  Vdev::Msix::Data_register_format data,
                                  bool lowest_prio)
  {
    if (lowest_prio)
      return logical_mode_lp(did, data);

    if (handle_broadcast(did, data))
      return nullptr;

    Vcpu_obj_registry *reg = nullptr;
    for (auto &lapic : _lapics)
      if (lapic && lapic->match_ldr(did))
        {
          lapic->set(data);
          reg = lapic->registry();
        }

    if (!reg)
      info().printf("No matching logical DestID: 0x%x, data 0x%llx\n", did,
                    data.raw);

    return reg;
  }

  cxx::Ref_ptr<Virt_lapic> get(unsigned core_no) const
  {
    return (core_no < _lapics.size()) ? _lapics[core_no] : nullptr;
  }

  void register_core(unsigned core_no, cxx::Ref_ptr<Vmm::Cpu_dev> cpu)
  {
    if (core_no < _lapics.size() && _lapics[core_no])
      {
        Dbg().printf("Local APIC for core %u already registered\n", core_no);
        return;
      }

    if (core_no >= _lapics.size())
      _lapics.resize(core_no + 1);

    _lapics[core_no] = Vdev::make_device<Virt_lapic>(core_no, cpu);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "LAPIC_array"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "LAPIC_array"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "LAPIC_array"); }

  /// true, iff `did` is a broadcast in the current LAPIC mode.
  bool is_broadcast(l4_uint32_t did) const
  {
    bool x2apic_mode = _lapics[0]->x2apic_mode();
    if (x2apic_mode)
      return 0xffffffffU == did;
    else
      return 0xffU == did;
  }

  /**
   * Handle broadcast MSI for logical and physical destination mode.
   *
   * \return True, iff `did` indicated a broadcast.
   */
  bool handle_broadcast(l4_uint32_t did, Vdev::Msix::Data_register_format data)
  {
    if (is_broadcast(did))
      {
        for (auto &lapic : _lapics)
          if (lapic)
            lapic->set(data);

        return true;
      }

    return false;
  }

  /// Handle logical mode MSI with lowest priority arbitration.
  Vcpu_obj_registry *logical_mode_lp(l4_uint32_t did,
                                     Vdev::Msix::Data_register_format data)
  {
    Virt_lapic *lowest = nullptr;
    for (auto &lapic : _lapics)
      {
        if (lapic && lapic->match_ldr(did))
          {
            if (!lowest)
              lowest = lapic.get();
            else if (lapic->task_prio_class() < lowest->task_prio_class())
              lowest = lapic.get();
          }
      }
    if (lowest)
      lowest->set(data);
    else
      warn().printf("Lowest priority aribitration for MSI failed. DestId 0x%x, "
                    "Data 0x%llx\n",
                    did, data.raw);

    // The assumption is that rebinding the interrupt is just not worth the
    // effort because the target changes dynamically.
    return nullptr;
  }

  std::vector<cxx::Ref_ptr<Virt_lapic>> _lapics;
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
    assert(vcpu_no < _icr.size());

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
    assert(vcpu_no < _icr.size());

    switch (msr)
      {
      case Icr_msr:
        // If the write originates from an MMIO access, only the lower 32bit of
        // the ICR should be written.
        if (mmio)
          _icr[vcpu_no] =
            (_icr[vcpu_no] & 0xffffffff00000000ULL) | (value & 0xffffffffULL);
        else
          _icr[vcpu_no] = value;
        // Vol. 3A 10.6.1: "The act of writing to the low doubleword of the ICR
        // causes the IPI to be sent."
        send_ipi(_icr[vcpu_no], vcpu_no, !mmio);
        return true;
      case Icr_mmio_ext:
        _icr[vcpu_no] = (_icr[vcpu_no] & 0xffffffffULL) | (value << 32);
        return true;
      default:
        return false;
      }
  }

  /**
   * Register the CPU device array with the IPI handler.
   *
   * \param cpus  Pointer to the CPU container.
   *
   * \pre The `cpus` array has already been populated.
   */
  void register_cpus(cxx::Ref_ptr<Vmm::Cpu_dev_array> const &cpus)
  {
    _cpus = cpus;
    _icr.resize(cpus->size());
  }

  /**
   * Register the MSI-X Controller with the IPI handler.
   *
   * \param msix_ctrl  Pointer to the MSI-X Controller.
   */
  void register_msix_ctrl(cxx::Ref_ptr<Msix_controller> const &msix_ctrl)
  { _msix_ctrl = msix_ctrl; }

private:
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "IPI"); }
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "IPI"); }

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

    if (data.delivery_mode() == Vdev::Msix::Delivery_mode::Dm_init
        || data.delivery_mode() == Vdev::Msix::Delivery_mode::Dm_startup)
      {
        // filter deassert IPIs; HW does not support these since Pentium D.
        if (data.delivery_mode() == Vdev::Msix::Delivery_mode::Dm_init
            && icr.trigger_mode() == 1 && icr.trigger_level() == 0)
          {
            trace().printf("{INIT,STARTUP} IPI: INIT deassert filtered. ICR: "
                           "0x%llx\n", icr.raw);
            return;
          }

        // filter unsupported destination modes
        switch (icr.dest_shorthand())
          {
          case Destination_shorthand::Self:
          case Destination_shorthand::All_including_self:
            info().printf(
              "{INIT,STARTUP} IPI: unsupported destination shorthand. Ignoring.\n");
            return;
          default:
            break;
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
        addr.dest_mode() = 0; // physical addressing
        _msix_ctrl->send(addr.raw, data.raw);
        break;
      case Destination_shorthand::All_including_self:
        // specify a physical broadcast MSI to be handled by Lapic_array
        addr.dest_id() = 0xffU;
        addr.dest_id_upper() = x2apic ? 0xfffffffUL : 0x0UL;
        addr.dest_mode() = 0;
        _msix_ctrl->send(addr.raw, data.raw);
        break;
      case Destination_shorthand::All_excluding_self:
        // Intel SDM: Translates to physical destination mode broadcast IPI.
        // Emulate the broadcast with single MSI for each vCPU.
        for (unsigned i = 0; i <= _cpus->max_cpuid(); ++i)
          {
            if (i == vcpu_no)
              continue;
            addr.dest_id() = i & 0xffU;
            addr.dest_id_upper() = x2apic ? i >> 8 : 0U;
            addr.dest_mode() = 0; // physical addressing
            _msix_ctrl->send(addr.raw, data.raw);
          }
        break;
      }
  }

  std::vector<l4_uint64_t> _icr;
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

  char const *dev_name() const override { return "Lapic_access_handler"; }

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

  /// Analyse the MSI-X message and send it to the specified local APIC.
  Vcpu_obj_registry *send(l4_uint64_t msix_addr, l4_uint64_t msix_data,
                          l4_uint32_t) const override
  {
    Vdev::Msix::Interrupt_request_compat addr(msix_addr);
    Vdev::Msix::Data_register_format data(msix_data);

    // Always use the extended MSI-X format. If not in use, the upper bits will
    // simply be 0. cf.  Intel Virtualization Technology for Directed I/O
    // Architecture Specification (June 2019) 5.1.8
    l4_uint32_t id = (addr.dest_id_upper() << 8) | addr.dest_id();

    if (addr.fixed() != Vdev::Msix::Address_interrupt_prefix)
      {
        trace().printf("Interrupt request prefix invalid; MSI dropped.\n");
        return nullptr;
      }

  // If RH is set, we do lowest priority arbitration!
  // We can only do lowest prio arbitration in logical addressing mode.
  // Therefore, we ignore the RH bit in physical addressing mode.
  // The same is true when the delivery mode is set to lowest priority.
  // The encoding physical mode, broadcast ID and lowest priority is
  // forbidden/undefined. Process it as physical broadcast just in case.
  if (addr.dest_mode())
    {
      bool lowest_prio =
        addr.redirect_hint()
        || (data.delivery_mode() == Vdev::Msix::Dm_lowest_prio);

      return _apics->logical_mode(id, data, lowest_prio);
    }
  else
    return _apics->physical_mode(id, data);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "MSI-CTLR"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "MSI-CTLR"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "MSI-CTLR"); }

  cxx::Ref_ptr<Lapic_array> _apics;
}; // class Msix_control

/**
 * Apic_timer; emulates a local APIC timer.
 *
 * Be aware that expired() is run on the timer thread with higher priority
 * than the vcpu thread, which handles everything else. So whenever an IPC is
 * involved, such as in enqueue_timeout(), dequeue_timeout() or irq_tigger()
 * you must not hold the mutex.
 */
class Apic_timer: public Vdev::Timer,
                  public L4::Ipc_svr::Timeout_queue::Timeout
{
  enum Timer
  {
    Frequency_hz = 1000000000ULL, // 1Ghz
    Microseconds_per_second = 1000000ULL,
  };

  /// Divide Configuration Register
  struct Divide_configuration_reg
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER_RO(3, 3, upper, raw);
    CXX_BITFIELD_MEMBER_RO(0, 1, lower, raw);

    Divide_configuration_reg() : raw(0U) {}
    Divide_configuration_reg(l4_uint32_t val) : raw(val) {}
    Divide_configuration_reg(Divide_configuration_reg const &o) : raw(o.raw) {}

    Divide_configuration_reg &operator= (const Divide_configuration_reg &)
      = default;

    unsigned divisor() const
    {
      unsigned shift = lower() + (upper() << 2);

      return shift == 7 ? 1 : 2u << shift;
    }
  };

  /// LVT Timer Register
  struct Lvt_timer_reg
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER(17, 18, mode, raw);
    CXX_BITFIELD_MEMBER(16, 16, masked, raw);
    CXX_BITFIELD_MEMBER(12, 12, pending, raw);
    CXX_BITFIELD_MEMBER(0, 7, vector, raw);

    Lvt_timer_reg() : raw(0x00010000) {}
    explicit Lvt_timer_reg(l4_uint32_t t) : raw(t) {}

    Lvt_timer_reg &operator = (l4_uint32_t t) { raw = t; return *this; }

    bool one_shot() const { return !mode(); }
    bool periodic() const { return mode() == 1; }
    bool tsc_deadline() const { return mode() == 2; }
    void disarm() { masked() = 1; }
    char const *mode_string()
    {
      if (one_shot())
        return "one shot";
      if (periodic())
        return "periodic";
      if (tsc_deadline())
        return "tsc deadline";
      return "unknown";
    }

    void print()
    {
      warn().printf("timer: %s %s %s vector: %u\n",
                    mode_string(),
                    masked() ? "masked" : "unmasked",
                    pending() ? "pending" : "",
                    vector().get());
    }
  };

public:
  Apic_timer(Virt_lapic *lapic)
  : _tmr_cur(0), _tmr_init(0), _div_reg(0), _lvt_reg(0x10000),
    _virt_lapic(lapic)
  {}

  l4_uint64_t read_tmr_cur()
  {
    std::lock_guard<std::mutex> lock(_tmr_mutex);

    // In deadline mode the current count register always returns 0
    if (_lvt_reg.tsc_deadline())
      return 0;

    if (_tmr_init == 0)
      return 0;

    l4_cpu_time_t now = l4_rdtsc();
    l4_cpu_time_t diff_us = l4_tsc_to_us(now - _tsc_base);
    l4_cpu_time_t frequency = Timer::Frequency_hz / _div_reg.divisor();
    l4_cpu_time_t diff_ticks =
      diff_us * frequency / Timer::Microseconds_per_second;

    if (_lvt_reg.periodic())
      {
        _tmr_cur = (_tmr_init - diff_ticks) % _tmr_init;
        return _tmr_cur;
      }

    if (diff_ticks >= _tmr_init)
      _tmr_cur = 0;
    else
      _tmr_cur = _tmr_init - diff_ticks;

    /// we do not inject interrupts here, but let them be injected from the
    /// timer thread (expired())

    return _tmr_cur;
  }

  /**
   * Reads the tmr_init field.
   *
   * _tmr_init is only used on the vcpu thread, therefore we do not need to
   * grab a lock.
   **/
  l4_uint64_t read_tmr_init()
  {
    return _tmr_init;
  }

  /**
   * Calculate the next timeout in periodic and one_shot modes.
   *
   * The result is given in micro seconds (10^-6 seconds). The APIC timer runs
   * with Timer::Frequency_hz. This function is also used in expired(),
   * therefore we must take care of the mutex.
   *
   * \param ticks The requested amount of ticks of the APIC timer.
   */
  l4_uint64_t next_timeout_us(l4_uint64_t ticks)
  {
    l4_uint64_t divisor;
    {
      std::lock_guard<std::mutex> lock(_tmr_mutex);
      divisor = _div_reg.divisor();
    }

    l4_kernel_clock_t kip = l4_kip_clock(l4re_kip());
    l4_cpu_time_t frequency = Timer::Frequency_hz / divisor;
    l4_cpu_time_t timeout_us =
      ticks * Timer::Microseconds_per_second / frequency;

    return kip + timeout_us;
  }

  void write_tmr_init(l4_uint64_t value)
  {
    // in tsc deadline mode writes to tmr_init are ignored
    if (_lvt_reg.tsc_deadline())
      return;

    // reset old timeouts
    dequeue_timeout(this);

    Lvt_timer_reg lvt;
    {
      std::lock_guard<std::mutex> lock(_tmr_mutex);

      lvt = Lvt_timer_reg(_lvt_reg);
      _tmr_init = value;
      _tmr_cur = value;
      _tsc_base = l4_rdtsc();
    }

    if (value)
      enqueue_timeout(this, next_timeout_us(value));
  }

  // _div_reg is only manipulated on the vcpu thread
  // therefore we don't need a lock
  l4_uint32_t read_divide_configuration_reg()
  { return _div_reg.raw; }

  void write_divide_configuration_reg(l4_uint32_t value)
  {
    l4_uint64_t init;
    Lvt_timer_reg lvt;
    {
      std::lock_guard<std::mutex> lock(_tmr_mutex);

      lvt = Lvt_timer_reg(_lvt_reg);
      _div_reg.raw = value;
      init = _tmr_init;
    }

    // changing this value modifies the speed of the APIC timer
    // so we must reset the timeouts that we set up with the
    // previous value

    // the TSC Deadline timer is not affected by this
    if (!lvt.tsc_deadline())
      dequeue_timeout(this);

    // only iff the guest programmed the timer do we need to set it up
    if (init)
      enqueue_timeout(this, next_timeout_us(init));
  }

  l4_uint32_t read_lvt_timer_reg()
  { return _lvt_reg.raw; }

  void write_lvt_timer_reg(l4_uint64_t value)
  {
    Lvt_timer_reg old_lvt(0);
    Lvt_timer_reg new_lvt(value);

    {
      std::lock_guard<std::mutex> lock(_tmr_mutex);
      old_lvt.raw = _lvt_reg.raw;
      _lvt_reg.raw = value;
    }

    if (old_lvt.pending() && !new_lvt.masked()
        && old_lvt.vector() == new_lvt.vector())
      irq_trigger(old_lvt.vector());

    // setting a new timer mode disarms the timer
    if (old_lvt.mode() != new_lvt.mode())
      dequeue_timeout(this);
  }

  // timeout has expired
  // inject interrupt iff periodic reenqueue to receive the next interrupt
  // Note: this function is called on the timer thread
  void expired()
  {
    bool periodic = false;
    bool masked = false;
    unsigned vector;
    l4_uint64_t init;

    {
      std::lock_guard<std::mutex> lock(_tmr_mutex);
      if (_lvt_reg.masked())
        _lvt_reg.pending() = 1;

      if (_lvt_reg.one_shot())
        _tmr_cur = 0;

      if (_lvt_reg.periodic())
        {
          periodic = true;
          _tmr_cur = _tmr_init;
        }

      init = _tmr_init;
      vector = _lvt_reg.vector();
      masked = _lvt_reg.masked();
      _tsc_deadline = 0;
    }

    if (!masked)
      irq_trigger(vector);

    if (periodic)
      requeue_timeout(this, next_timeout_us(init));
  }

  l4_uint64_t read_tsc_deadline_msr()
  {
    std::lock_guard<std::mutex> lock(_tmr_mutex);
    if (!_lvt_reg.tsc_deadline())
      return 0ULL;
    return _tsc_deadline;
  }

  void write_tsc_deadline_msr(l4_uint64_t target_tsc)
  {
    // a fresh TSC deadline value always resets previous timeouts
    dequeue_timeout(this);

    bool tsc_deadline_mode;
    bool masked = false;
    {
      std::lock_guard<std::mutex> lock(_tmr_mutex);
      tsc_deadline_mode = _lvt_reg.tsc_deadline();
      masked = _lvt_reg.masked();
      _tsc_deadline = target_tsc;

    }

    if (!tsc_deadline_mode)
      {
        if (!masked)
          warn()
            .printf("guest programmed tsc deadline, but tsc deadline mode not "
                    "set. new_tsc 0x%llx, LVT: %s\n",
                    target_tsc, _lvt_reg.mode_string());
        return;
      }

    // writing a zero disarms the timer
    if (target_tsc == 0)
      return;

    l4_kernel_clock_t tsc_diff;
    l4_cpu_time_t tsc = l4_rdtsc();
    if (target_tsc <= tsc)
      tsc_diff = 0;
    else
      tsc_diff = target_tsc - tsc;

    if (0)
      Dbg()
        .printf("New TSC deadline: 0x%llx (now: 0x%llx) timer status: %x\n",
                target_tsc, tsc, _lvt_reg.raw);

    l4_kernel_clock_t t = l4_tsc_to_us(tsc_diff);
    l4_kernel_clock_t kip = l4_kip_clock(l4re_kip());
    enqueue_timeout(this, kip + t);
  }

private:
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "LAPIC-Timer"); }

  void irq_trigger(l4_uint32_t irq)
  { _virt_lapic->irq_trigger(irq); }

  l4_uint64_t _tmr_cur, _tmr_init, _tsc_base;
  Divide_configuration_reg _div_reg;
  Lvt_timer_reg _lvt_reg;
  Virt_lapic *_virt_lapic;
  l4_uint64_t _tsc_deadline;
  std::mutex _tmr_mutex;
}; // class Apic_timer

} // namespace Gic
