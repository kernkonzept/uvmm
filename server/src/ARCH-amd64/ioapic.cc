/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "device_factory.h"
#include "guest.h"
#include "ioapic.h"

namespace Gic {

  l4_uint64_t Io_apic::read(unsigned reg, char, unsigned cpu_id)
  {
    switch (reg)
      {
      case Ioregsel:
        return _ioregsel;
      case Iowin:
        switch (_ioregsel.load())
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
                  warn().printf("Unimplemented MMIO read from ioregsel "
                                "register 0x%x\n", _ioregsel.load());
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

  void Io_apic::write(unsigned reg, char, l4_uint64_t value, unsigned cpu_id)
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
              warn()
                .printf("Unimplemented MMIO write to ioregsel register 0x%x\n",
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

  void Io_apic::set(unsigned irq)
  {
    // send to PIC. (TODO only if line is masked at IOAPIC?)
    if (irq < 16) // PIC can handle only the first 16 lines
      _pic->set(irq);

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

} // namespace Gic


namespace {

  struct F : Vdev::Factory
  {
    cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                      Vdev::Dt_node const &node) override
    {
      auto msi_distr = devs->get_or_create_mc_dev(node);
      // Create the legacy PIC device here to forward legacy Interrupts.
      auto pic = Vdev::make_device<Vdev::Legacy_pic>(msi_distr);
      auto io_apic = Vdev::make_device<Gic::Io_apic>(msi_distr, pic);
      devs->vmm()->add_mmio_device(io_apic->mmio_region(), io_apic);

      // Register legacy PIC IO-ports
      devs->vmm()->add_io_device(Vmm::Io_region(0x20, 0x21,
                                                Vmm::Region_type::Virtual),
                                 pic->master());
      devs->vmm()->add_io_device(Vmm::Io_region(0xA0, 0xA1,
                                                Vmm::Region_type::Virtual),
                                 pic->slave());
      return io_apic;
    }
  };

  static F f;
  static Vdev::Device_type d = {"intel,ioapic", nullptr, &f};

}
