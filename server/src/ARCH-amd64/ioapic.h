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

namespace Gic {

/**
 * Virtual IOAPIC implementation of a 82093AA.
 *
 * TODO The Ic interface is a bit off, as there is no way to clear an IRQ, as
 * the IOAPIC sends an MSI to the MSI-controller when a device sends a legacy
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
    l4_uint64_t raw = 1ULL << 48;

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

  Io_apic(cxx::Ref_ptr<Gic::Msix_controller> distr)
  : _distr(distr), _id(Io_apic_id << Io_apic_id_offset), _ioregsel(0), _iowin(0)
  {}

  // Mmio device interface
  l4_uint64_t read(unsigned reg, char, unsigned cpu_id)
  {
    switch (reg)
      {
      case Ioregsel:
        return _ioregsel;
      case Iowin:
        switch (_ioregsel)
          {
          case Id_reg:
            return _id;
          case Version_reg:
            return Io_apic_ver | ((Io_apic_num_pins - 1) << 16);
          case Arbitration_reg:
            return _id;
          default:
            {
              unsigned index = _ioregsel - Redir_tbl_offset_reg;
              unsigned irq = index / 2;
              if (irq >= Io_apic_num_pins)
                {
                  warn().printf("Unimplemented MMIO read from ioregsel register 0x%x\n",
                                _ioregsel.load());
                  return -1;
                }

              if (index % 2)
                return _redirect_tbl[irq].load().upper_reg();
              else
                return _redirect_tbl[irq].load().lower_reg();
            }
          }
        break;
      default:
        warn().printf("Unimplemented MMIO read from register %d by CPU %d\n",
                      reg, cpu_id);
        return -1;
      }
  }

  void write(unsigned reg, char, l4_uint64_t value, unsigned cpu_id)
  {
    switch (reg)
      {
      case Ioregsel:
        _ioregsel = value & 0xff;
        break;
      case Iowin:
        {
          if (_ioregsel == Id_reg)
            {
              _id = value;
              break;
            }

          unsigned index = _ioregsel - Redir_tbl_offset_reg;
          unsigned irq = index / 2;
          if (irq >= Io_apic_num_pins)
            {
              warn().printf("Unimplemented MMIO write to ioregsel register 0x%x\n",
                           _ioregsel.load());
              break;
            }

          Redir_tbl_entry e = _redirect_tbl[irq];
          if (index % 2)
            e.upper_reg() = value;
          else
            {
              // ignore writes to RO fields
              value = (value & ~Redir_tbl_entry::Ro_mask)
                | e.delivery_status() | e.remote_irr();
              e.lower_reg() = value;
            }

          _redirect_tbl[irq] = e; // atomic store
          break;
        }
      default:
        warn().printf("Unimplemented MMIO write to register %d by CPU %d\n",
                      reg, cpu_id);
        break;
      }
  }

  // IC interface
  void set(unsigned irq) override
  {
    Redir_tbl_entry entry = redirect(irq);
    if (entry.masked())
      return;

    Vdev::Msix::Data_register_format data(entry.vector());
    data.trigger_mode() = entry.trigger_mode();
    data.trigger_level() = !entry.pin_polarity(); // it's actually inverted.
    data.delivery_mode() = entry.delivery_mode();

    Vdev::Msix::Interrupt_request_compat addr(0ULL);
    addr.dest_id() = entry.dest_id();
    addr.dest_mode() = entry.dest_mode();
    addr.fixed() = Vdev::Msix::Address_interrupt_prefix;

    _distr->send(addr.raw, data.raw);
  }

  void clear(unsigned) override {}

  // XXX unclear if this function is used. Required by Gic::Ic.
  // Dummy implementation.
  void bind_eoi_handler(unsigned irq, Eoi_handler *handler) override
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
  Eoi_handler *get_eoi_handler(unsigned irq) const override
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
  Gic::Eoi_handler *_sources[Io_apic_num_pins] = {nullptr, };
}; // class Io_apic

} // namespace Gic
