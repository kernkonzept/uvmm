/*
 * Copyright (C) 2023-2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device_factory.h"
#include "guest.h"
#include "ioapic.h"

namespace Gic {

  l4_uint64_t Io_apic::read_reg(unsigned reg) const
  {
    switch (reg)
      {
      case Id_reg:
        return _id;
      case Version_reg:
        return Io_apic_ver | ((Io_apic_num_pins - 1) << 16);
      case Arbitration_reg:
        return _id;
      default:
        {
          unsigned index = reg - Redir_tbl_offset_reg;
          unsigned irq = index / 2;
          if (irq >= Io_apic_num_pins)
            {
              info().printf("Unimplemented MMIO read from ioregsel "
                            "register 0x%x\n", reg);
              return -1;
            }

          if (index % 2)
            return _redirect_tbl[irq].load().upper_reg();
          else
            return _redirect_tbl[irq].load().lower_reg()
                   & ~(1UL << Redir_tbl_entry::Nospec_level_set_bit);
        }
      }
  }

  void Io_apic::write_reg(unsigned reg, l4_uint64_t value)
  {
    if (reg == Id_reg)
      {
        _id = value;
        return;
      }

    unsigned index = reg - Redir_tbl_offset_reg;
    unsigned irq = index / 2;
    if (irq >= Io_apic_num_pins)
      {
        info().printf("Unimplemented MMIO write to ioregsel register 0x%x\n",
                      reg);
        return;
      }

    Redir_tbl_entry e = _redirect_tbl[irq];
    Redir_tbl_entry e_new;
    bool was_pending = e.is_pending();

     do
       {
         e_new = e;

         if (index % 2)
            e_new.upper_reg() = value;
         else
           {
             // ignore writes to RO fields
             value = (value & ~Redir_tbl_entry::Ro_mask)
                     | e_new.delivery_status().get_unshifted()
                     | e_new.remote_irr().get_unshifted();

             // retain level_set bit, if entry is still masked.
             if (   value & (1 << Redir_tbl_entry::Masked_bit)
                 && e_new.is_pending())
                value |= (1 << Redir_tbl_entry::Nospec_level_set_bit);

             e_new.lower_reg() = value;
           }
        }
      while (!_redirect_tbl[irq].compare_exchange_weak(e, e_new));

      if (!e_new.masked())
        apic_bind_irq_src_handler(irq, e_new.vector(), e_new.dest_id(),
                                  e_new.dest_mode());

      // in case of level-triggerd IRQs deliver IRQ since level is high.
      if (!e_new.masked() && was_pending)
        {
          trace()
            .printf("IRQ %i not masked anymore. send pending level irq\n",
                    irq);
           set(irq);
         }
      // no need to clear the level_set bit, we didn't write it into the new
      // entry above.
  }

  l4_uint64_t Io_apic::read(unsigned reg, char, unsigned cpu_id)
  {
    switch (reg)
      {
      case Ioregsel:
        return _ioregsel;
      case Iowin:
        return read_reg(_ioregsel.load());
      case Eoir:
        return 0UL;
      default:
        info().printf("Unimplemented MMIO read from register %d by CPU %d\n",
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
        write_reg(_ioregsel.load(), value);
        break;
      case Eoir:
        clear_all_rirr(value & 0xff);
        break;
      default:
        info().printf("Unimplemented MMIO write to register %d by CPU %d\n",
                      reg, cpu_id);
        break;
      }
  }

  void Io_apic::apic_bind_irq_src_handler(unsigned entry_num, unsigned vec,
                                          unsigned dest, unsigned dest_mod)
  {
    Ioapic_irq_src_handler *hdlr = &_apic_irq_src[entry_num];
    if (hdlr->vector != -1U)
      {
        // assumption: hdlr already bound
        if (hdlr->vector == vec)
          return;
        else
          apic_unbind_irq_src_handler(entry_num);
      }

    hdlr->vector = vec;
    hdlr->dest = dest;
    hdlr->dest_mod = dest_mod;
    do_apic_bind_irq_src_handler(hdlr, true);
  };

  void Io_apic::apic_unbind_irq_src_handler(unsigned entry_num)
  {
    Ioapic_irq_src_handler *hdlr = &_apic_irq_src[entry_num];
    if (hdlr->vector == -1U)
      // don't unbind handler if not bound
      return;

    do_apic_bind_irq_src_handler(hdlr, false);

    hdlr->vector = -1U;
    hdlr->dest = -1U;
    hdlr->dest_mod = 0U;
  }

  void Io_apic::do_apic_bind_irq_src_handler(Ioapic_irq_src_handler *hdlr,
                                             bool bind)
  {
    Ioapic_irq_src_handler *new_hdlr = bind ? hdlr : nullptr;

    if (hdlr->dest_mod == 0) // physical
      {
        auto apic = _lapics->get(hdlr->dest);
        if (apic)
          apic->bind_irq_src_handler(hdlr->vector, new_hdlr);
      }
    else
      _lapics->apics_bind_irq_src_handler_logical(hdlr->dest, hdlr->vector,
                                                  new_hdlr);
  }

  void Io_apic::set(unsigned irq)
  {
    // send to PIC. (TODO only if line is masked at IOAPIC?)
    if (irq < 16) // PIC can handle only the first 16 lines
      _pic->set(irq);

    Redir_tbl_entry entry = redirect(irq);
    if (entry.masked())
      {
        if (entry.is_level_triggered())
          // We must save the state of the level triggered IRQ, since we get
          // the softIRQ only once and can't query the current level.
          // We don't notice, if the actual HW line changes to no-IRQ again,
          // but that's better than losing an IRQ here.
          set_level_set(irq);
        return;
      }

    if (entry.remote_irr())
      {
        // ignore re-triggered level-triggered IRQs that are in-service at
        // local APIC
        return;
      }

    Vdev::Msix::Data_register_format data(entry.vector());
    data.trigger_mode() = entry.trigger_mode();
    data.trigger_level() = !entry.pin_polarity(); // it's actually inverted.
    data.delivery_mode() = entry.delivery_mode();

    Vdev::Msix::Interrupt_request_compat addr(0ULL);
    addr.dest_id() = entry.dest_id();
    addr.dest_mode() = entry.dest_mode();
    addr.fixed() = Vdev::Msix::Address_interrupt_prefix;

    _distr->send(addr.raw, data.raw);

    // update entry if necessary
    if (entry.is_level_triggered())
      set_remote_irr(irq);
  }

} // namespace Gic


namespace {

  struct F : Vdev::Factory
  {
    cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                      Vdev::Dt_node const &node) override
    {
      auto msi_distr = devs->get_or_create_mc_dev(node);
      auto apic_array = devs->vmm()->apic_array();
      // Create the legacy PIC device here to forward legacy Interrupts.
      auto pic = Vdev::make_device<Vdev::Legacy_pic>(msi_distr);
      auto io_apic =
        Vdev::make_device<Gic::Io_apic>(msi_distr, apic_array, pic);
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
