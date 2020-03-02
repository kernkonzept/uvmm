/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "io_device.h"
#include "device.h"
#include "irq.h"
#include "msi_arch.h"
#include "msi_controller.h"

namespace Vdev {

/**
 * Emulation of a programmable interrupt controller.
 *
 * Example of a device tree entry:
 *
 *   PIC: pic {
 *     compatible = "virt-pic";
 *     reg = <0x0 0x0 0x0 0x0>;
 *     msi-parent = <&msi_ctrl>;
 *     interrupt-controller;
 *     #interrupt-cells = <1>;
 *   };
 *
 * The PIC emulation provides the guest with the ability to assign the legacy
 * interrupts of the master and slave PIC to a software defined range of two
 * times eight consecutive interrupt numbers.
 * The emulation reacts to IO-ports 0x20/0x21 and 0xA0/0xA1 as Command/Data
 * port combination for the master and salve chips.
 */
class Legacy_pic : public Gic::Ic
{
  enum Ports
  {
    Cmd_port = 0,
    Data_port = 1,
  };

  enum Command : l4_uint8_t
  {
    None = 0,
    Eoi = 0x20,
    Eoi_lvl0 = 0x60,
    Init = 0x11,
    Read_irr = 0x0a,
    Read_isr = 0x0b,
  };

  enum class Init_words
  {
    None,
    Vector_offset,
    Wirring,
    Env_info,
  };

  /**
   * Single PIC-chip emulation handling IO-port access and interrupt offsets.
   */
  class Chip : public Vmm::Io_device
  {
    l4_uint8_t _cmd = Command::None;
    l4_uint8_t _mask = 0;
    l4_uint8_t _isr = 0;
    l4_uint8_t _irr = 0;

    Init_words _expect = Init_words::Vector_offset;
    l4_uint8_t _offset = 0;
    l4_uint8_t _slave_at = 0;
    l4_uint8_t _env = 0;

    bool _is_master;
    Legacy_pic *_pic;

  public:
    Chip(bool master, Legacy_pic *pic) : _is_master(master), _pic(pic)
    {}

    /// Check interrupt mask/in-service and return the IRQ number with offset.
    int trigger(unsigned irq)
    {
      if (_offset == 0)
        return -1;

      unsigned irq_bit = 1U << irq;

      if (_isr || _mask & irq_bit)
        {
          _irr |= irq_bit;
          return -1;
        }
      else
        {
          _isr |= irq_bit;
          return _offset + irq;
        }
    }

    /// Return the number of the first pending interrupt or -1.
    int check_pending()
    {
      if (_isr || ~(_irr & ~_mask))
        return -1;

      for (int i = 0; _irr >> i; ++i)
        {
          l4_uint8_t bit = 1U << i;

          if (_irr & bit)
          {
            _irr &= ~bit;
            _isr |= bit;
            return i;
          }
        }

      return -1;
    }

    /// Handle read accesses on the PICs command and data ports.
    void io_in(unsigned port, Vmm::Mem_access::Width width, l4_uint32_t *value)
    {
      *value = -1U;

      if (width != Vmm::Mem_access::Width::Wd8)
        return;

      switch (port)
        {
        case Cmd_port:
          switch (_cmd)
            {
            case Command::Read_irr: *value = _irr; break;
            case Command::Read_isr: *value = _isr; break;
            }
          break;

        case Data_port:
          if (_cmd == Command::None)
            {
              *value = _mask;
              trace().printf("%s read mask 0x%x\n",
                             _is_master ? "Master:" : "Slave:", _mask);
              break;
            }
          break;
        }

      trace().printf("%s port in: %s - 0x%x\n",
                     _is_master ? "Master:" : "Slave:",
                     port == 0 ? "cmd" : "data", *value);
    }

    /// Handle write accesses on the PICs command and data ports.
    void io_out(unsigned port, Vmm::Mem_access::Width width, l4_uint32_t value)
    {
      if (width != Vmm::Mem_access::Width::Wd8)
        return;

      trace().printf("%s port out: %s - 0x%x\n",
                     _is_master ? "Master:" : "Slave:",
                     port == 0 ? "cmd" : "data", value);

      switch (port)
        {
        case Cmd_port:
          switch (value)
            {
            case Command::Eoi:
            case Command::Eoi_lvl0:
              {
                _isr = 0;
                int irq = check_pending();
                if (irq != -1)
                  _pic->set(irq);
                break;
              }
            case Command::None:
              _cmd = Command::None;
              break;
            case Command::Init:
              _cmd = Command::Init;
              _expect = Init_words::Vector_offset;
              break;
            case Command::Read_irr:
              _cmd = Command::Read_irr;
              break;
            case Command::Read_isr:
              _cmd = Command::Read_isr;
              break;
            }
          break;

        case Data_port:
          if (_cmd == Command::None)
            {
              _mask = value;
              trace().printf("%s write mask 0x%x\n",
                             _is_master ? "Master:" : "Slave:", _mask);
            }

          if (_cmd == Command::Init)
            {
              switch (_expect)
                {
                case Init_words::None: break;
                case Init_words::Vector_offset:
                  _offset = value;
                  _expect = Init_words::Wirring;
                  warn().printf("%s: Vector offset %u\n",
                                _is_master ? "MASTER" : "SLAVE", _offset);
                  break;
                case Init_words::Wirring:
                  _slave_at = value;
                  _expect = Init_words::Env_info;
                  break;
                case Init_words::Env_info:
                  _env = value;
                  _expect = Init_words::None;
                  _cmd = Command::None;
                  break;
                }
            }
        }
    }
  };

public:
  /**
   * Create a legacy PIC consisting of a master and slave chip.
   *
   * \param distr  MSI-parent to send interrupts to.
   */
  Legacy_pic(cxx::Ref_ptr<Gic::Msix_controller> distr)
  : _master(Vdev::make_device<Chip>(true, this)),
    _slave(Vdev::make_device<Chip>(false, this)),
    _distr(distr)
  {
    info().printf("Hello, Legacy_pic\n");
  }

  /// Issue a legacy interrupt in range [0, 15]
  void set(unsigned irq) override
  {
    assert(irq < 16);

    int num = irq < 8 ? _master->trigger(irq) : _slave->trigger(irq - 8);
    // Do we need to set the _master line where the slave is wired to?
    if (num >= 32)
      {
        using namespace Vdev::Msix;

        Interrupt_request_compat addr(0ULL);
        // dest_id = 0, redirect_hint = 0, dest_mode = 0;
        addr.fixed() = Address_interrupt_prefix;

        Data_register_format data(0U);
        data.vector() = num;
        data.delivery_mode() = Dm_extint;

        _distr->send(addr.raw, data.raw);
      }
  };

  void clear(unsigned) override {}

  void bind_eoi_handler(unsigned, Gic::Eoi_handler *) override
  { assert(false); }

  Gic::Eoi_handler *get_eoi_handler(unsigned) const override
  {
    return nullptr;
  }

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override
  {
    enum { Irq_cells = 1, };

    if (propsz < Irq_cells)
      return -L4_ERANGE;

    if (read)
      *read = Irq_cells;

    return fdt32_to_cpu(prop[0]);
  }

  /// Obtain a pointer to the master PIC chip.
  cxx::Ref_ptr<Chip> master() const { return _master; }
  /// Obtain a pointer to the slave PIC chip.
  cxx::Ref_ptr<Chip> slave() const { return _slave; }

private:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "PIC"); }
  static Dbg info() { return Dbg(Dbg::Irq, Dbg::Info, "PIC"); }
  static Dbg warn() { return Dbg(Dbg::Irq, Dbg::Warn, "PIC"); }

  cxx::Ref_ptr<Chip> _master;
  cxx::Ref_ptr<Chip> _slave;
  cxx::Ref_ptr<Gic::Msix_controller> _distr;
};

} // namespace Vdev
