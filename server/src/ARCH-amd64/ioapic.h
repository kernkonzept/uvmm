/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
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
 * TODO The Ic interface is a bit off, as there is no way to clear an IRQ, as
 * the IOAPIC sends an MSI to the MSI-controller when a device sends a legacy
 * IRQ.
 *  set: send an MSI instead of the legacy IRQ (programmed by OS)
 *  clear: nop
 *  bind_irq_src_handler:  ?
 *  get_irq_src_handler: ?
 *  dt_get_interrupt: parse DT
 *
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
      Ro_mask = 1U << Delivery_status_bit | 1U << Remote_irr_bit,
    };

    Redir_tbl_entry() noexcept = default;
    // The IOAPIC spec mentions bit 48, which is specified as reserved, bit 16
    // is the mask bit and I think it's sane to start out with masked vectors.
    l4_uint64_t raw = 1ULL << 16;

    CXX_BITFIELD_MEMBER_RO(56, 63, dest_id, raw);
    CXX_BITFIELD_MEMBER_RO(16, 16, masked, raw);
    CXX_BITFIELD_MEMBER_RO(15, 15, trigger_mode, raw);
    CXX_BITFIELD_MEMBER_RO(14, 14, remote_irr, raw);
    CXX_BITFIELD_MEMBER_RO(13, 13, pin_polarity, raw);
    CXX_BITFIELD_MEMBER_RO(12, 12, delivery_status, raw);
    CXX_BITFIELD_MEMBER_RO(11, 11, dest_mode, raw);
    CXX_BITFIELD_MEMBER_RO(8, 10, delivery_mode, raw);
    CXX_BITFIELD_MEMBER_RO(0, 7, vector, raw);

    // Redirection Table entries can only be written as DWORD.
    CXX_BITFIELD_MEMBER(0, 31, lower_reg, raw);
    CXX_BITFIELD_MEMBER(32, 63, upper_reg, raw);
  };

public:
  enum
  {
    Mmio_addr = 0xfec00000,
  };

  Io_apic(cxx::Ref_ptr<Gic::Msix_controller> distr,
          cxx::Ref_ptr<Vdev::Legacy_pic> pic)
  : _distr(distr), _id(Io_apic_id << Io_apic_id_offset), _ioregsel(0), _iowin(0),
    _pic(pic)
  {}

  // Mmio device interface
  l4_uint64_t read(unsigned reg, char, unsigned cpu_id);
  void write(unsigned reg, char, l4_uint64_t value, unsigned cpu_id);

  // IC interface
  void set(unsigned irq) override;
  void clear(unsigned) override {}

  // XXX unclear if this function is used. Required by Gic::Ic.
  // Dummy implementation.
  void bind_irq_src_handler(unsigned irq, Irq_src_handler *handler) override
  {
    if (irq >= Io_apic_num_pins)
      {
        warn().printf("Try to bind out-of-range IRQ %u. Ignoring. \n", irq);
        return;
      }
    if (handler && _sources[irq])
      throw L4::Runtime_error(-L4_EEXIST);
    _sources[irq] = handler;
  }

  // XXX unclear if this function is used. Required by Gic::Ic.
  // Dummy implementation.
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

  /// Return the redirection table entry for given `irq`.
  Redir_tbl_entry redirect(unsigned irq) const
  {
    assert(irq < Io_apic_num_pins);
    return _redirect_tbl[irq];
  }

  cxx::Ref_ptr<Gic::Msix_controller> _distr;
  std::atomic<l4_uint32_t> _id;
  std::atomic<l4_uint32_t> _ioregsel;
  std::atomic<l4_uint32_t> _iowin;
  std::atomic<Redir_tbl_entry> _redirect_tbl[Io_apic_num_pins];
  Gic::Irq_src_handler *_sources[Io_apic_num_pins] = {};
  cxx::Ref_ptr<Vdev::Legacy_pic> _pic;
}; // class Io_apic

} // namespace Gic
