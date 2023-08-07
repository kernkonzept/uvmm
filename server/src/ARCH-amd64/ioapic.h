/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include "mmio_device.h"
#include "debug.h"
#include "irq.h"
#include "msi_controller.h"
#include "msix.h"
#include "msi_arch.h"
#include "legacy_pic.h"

namespace Gic {

/**
 * Virtual IOAPIC implementation of a 82093AA.
 *
 * The IOAPIC sends legacy IRQs onwards as MSI as programmed into the
 * redirection table by the guest.
 */
class Io_apic : public Ic, public Vmm::Mmio_device_t<Io_apic>
{
  enum
  {
    Io_apic_id = 0,
    Io_apic_id_offset = 24,
    Io_apic_ver = 0x11,
    Io_apic_num_pins = 24,
    Io_apic_mem_size = 0x1000,
    Irq_cells = 1, // keep in sync with virt-pc.dts
  };

  enum Ioapic_mmio_regs
  {
    Ioregsel = 0,
    Iowin = 0x10,
  };

  enum Ioapic_regs
  {
    Id_reg = 0,
    Version_reg = 1,
    Arbitration_reg = 2,
    Redir_tbl_offset_reg = 0x10,
  };

  struct Redir_tbl_entry
  {
    enum
    {
      Delivery_status_bit = 12,
      Remote_irr_bit = 14,
      Masked_bit = 16,
      Nospec_level_set_bit = 17,
      Ro_mask = 1U << Nospec_level_set_bit | 1U << Delivery_status_bit
                | 1U << Remote_irr_bit,
    };

    Redir_tbl_entry() noexcept = default;
    // The IOAPIC spec mentions bit 48, which is specified as reserved, bit 16
    // is the mask bit and I think it's sane to start out with masked vectors.
    l4_uint64_t raw = 1ULL << 16;

    bool is_level_triggered() const { return trigger_mode(); }
    bool is_pending() { return is_level_triggered() && level_set(); }

    CXX_BITFIELD_MEMBER_RO(56, 63, dest_id, raw);
    // use reserved bit for internal state of level triggered input line.
    // only relevant, if line is masked
    CXX_BITFIELD_MEMBER(17, 17, level_set, raw);
    CXX_BITFIELD_MEMBER_RO(16, 16, masked, raw);
    CXX_BITFIELD_MEMBER_RO(15, 15, trigger_mode, raw);
    CXX_BITFIELD_MEMBER(14, 14, remote_irr, raw);
    CXX_BITFIELD_MEMBER_RO(13, 13, pin_polarity, raw);
    CXX_BITFIELD_MEMBER_RO(12, 12, delivery_status, raw);
    CXX_BITFIELD_MEMBER_RO(11, 11, dest_mode, raw);
    CXX_BITFIELD_MEMBER_RO(8, 10, delivery_mode, raw);
    CXX_BITFIELD_MEMBER_RO(0, 7, vector, raw);

    // Redirection Table entries can only be written as DWORD.
    CXX_BITFIELD_MEMBER(0, 31, lower_reg, raw);
    CXX_BITFIELD_MEMBER(32, 63, upper_reg, raw);
  };

  struct Ioapic_irq_src_handler : public Irq_src_handler
  {
    void eoi() override
    {
      assert(ioapic != nullptr);

      // clear state in redirection table entry
      ioapic->entry_eoi(irq_num);

      {
        // MSI generated from the IRQ can have multiple target cores. If this
        // IRQ/MSI is level triggered, multiple cores would send an EOI.
        // Would be insane, but who knows.
        std::lock_guard<std::mutex> lock(_mtx);

        // get IRQ src handler of input IRQ and forward EOI signal
        Irq_src_handler *hdlr = ioapic->get_irq_src_handler(irq_num);
        if (hdlr)
          hdlr->eoi();
      }
    }

    unsigned irq_num = 0;
    Io_apic *ioapic = nullptr;
    unsigned vector = -1U;
    unsigned dest = -1U;
    unsigned dest_mod = 0; // default: physical
  private:
    std::mutex _mtx;
  };

public:
  enum
  {
    Mmio_addr = 0xfec00000,
  };

  Io_apic(cxx::Ref_ptr<Gic::Msix_controller> distr,
          cxx::Ref_ptr<Gic::Lapic_array> apic_array,
          cxx::Ref_ptr<Vdev::Legacy_pic> pic)
  : _distr(distr), _lapics(apic_array),
    _id(Io_apic_id << Io_apic_id_offset), _ioregsel(0), _iowin(0),
    _pic(pic)
  {
    // initialize IRQ src handler for LAPIC communication
    for (unsigned i = 0; i < Io_apic_num_pins; ++i)
      {
        _apic_irq_src[i].irq_num = i;
        _apic_irq_src[i].ioapic = this;
      }
  }

  // Mmio device interface
  l4_uint64_t read(unsigned reg, char, unsigned cpu_id);
  void write(unsigned reg, char, l4_uint64_t value, unsigned cpu_id);

  // IC interface
  void set(unsigned irq) override;
  void clear(unsigned) override {}

  /**
   * Bind the IRQ src handler of a level-triggered legacy interrupt.
   *
   * This handler is signaled, if the IOAPIC receives an EOI signal from the
   * local APIC for the corresponding interrupt line.
   */
  void bind_irq_src_handler(unsigned irq, Irq_src_handler *handler) override
  {
    if (irq >= Io_apic_num_pins)
      {
        warn().printf("Try to bind out-of-range IRQ %u. Ignoring. \n", irq);
        return;
      }
    if (handler && _sources[irq])
      L4Re::throw_error(-L4_EEXIST, "Bind IRQ src handler at IOAPIC." );
    _sources[irq] = handler;
  }

  /**
   * Get IRQ src handler bound for the given legacy interrupt line or
   * `nullptr` if no handler is bound.
   */
  Irq_src_handler *get_irq_src_handler(unsigned irq) const override
  {
    if (irq >= Io_apic_num_pins)
      {
        warn().printf("Try to get out-of-range IRQ %u. Ignoring. \n", irq);
        return nullptr;
      }
    return _sources[irq];
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

  char const *dev_name() const override { return "Ioapic"; }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "IOAPIC"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "IOAPIC"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "IOAPIC"); }

  l4_uint64_t read_reg(unsigned reg) const;
  void write_reg(unsigned reg, l4_uint64_t value);

  /// Return the redirection table entry for given `irq`.
  Redir_tbl_entry redirect(unsigned irq) const
  {
    assert(irq < Io_apic_num_pins);
    return _redirect_tbl[irq];
  }

  void entry_eoi(unsigned irq)
  {
    assert(irq < Io_apic_num_pins);

    // clear remote_irr and for level triggered the level_set bit.
    Redir_tbl_entry e = _redirect_tbl[irq];
    Redir_tbl_entry e_new;

    do
      {
        e_new = e;
        e_new.remote_irr() = 0;
        e_new.level_set() = 0;
      }
    while (!_redirect_tbl[irq].compare_exchange_weak(e, e_new));
  }

  void set_level_set(unsigned irq)
  {
    assert(irq < Io_apic_num_pins);

    Redir_tbl_entry e = _redirect_tbl[irq];
    Redir_tbl_entry e_new;

    do
      {
        e_new = e;
        e_new.level_set() = 1;
      }
    while (!_redirect_tbl[irq].compare_exchange_weak(e, e_new));
  }

  void set_remote_irr(unsigned irq)
  {
    assert(irq < Io_apic_num_pins);

    Redir_tbl_entry e = _redirect_tbl[irq];
    Redir_tbl_entry e_new;

    do
      {
        e_new = e;
        e_new.remote_irr() = 1;
      }
    while (!_redirect_tbl[irq].compare_exchange_weak(e, e_new));
  }

  void apic_bind_irq_src_handler(unsigned entry_num, unsigned vec,
                                 unsigned dest, unsigned dest_mod);
  void apic_unbind_irq_src_handler(unsigned entry_num);
  void do_apic_bind_irq_src_handler(Ioapic_irq_src_handler *hdlr, bool bind);

  cxx::Ref_ptr<Gic::Msix_controller> _distr;
  cxx::Ref_ptr<Lapic_array> _lapics;
  std::atomic<l4_uint32_t> _id;
  std::atomic<l4_uint32_t> _ioregsel;
  std::atomic<l4_uint32_t> _iowin;
  std::atomic<Redir_tbl_entry> _redirect_tbl[Io_apic_num_pins];
  Gic::Irq_src_handler *_sources[Io_apic_num_pins] = {};
  cxx::Ref_ptr<Vdev::Legacy_pic> _pic;
  Ioapic_irq_src_handler _apic_irq_src[Io_apic_num_pins];
}; // class Io_apic

} // namespace Gic
