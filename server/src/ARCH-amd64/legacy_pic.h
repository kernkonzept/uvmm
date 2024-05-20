/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include "io_device.h"
#include "device.h"
#include "irq.h"
#include "msi_arch.h"
#include "msi_controller.h"

#include <l4/cxx/bitfield>

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
 * port combination for the master and slave chips.
 */
class Legacy_pic : public Gic::Ic
{
  enum Config
  {
    Num_irqs = 16 // Number of IRQs supported by PIC
  };

  enum Ports
  {
    Cmd_port = 0,
    Data_port = 1,
  };

  enum class Init_words
  {
    ICW1 = 0,
    ICW2,
    ICW3,
    ICW4,
  };

  /**
   * Single PIC-chip emulation handling IO-port access and interrupt offsets.
   */
  class Chip : public Vmm::Io_device
  {
    // Register set
    // We only support ICW1 == 0x11. (ICW4 | INIT).
    struct ICW1
    {
      l4_uint8_t raw;

      CXX_BITFIELD_MEMBER(0, 0, icw4, raw);
      CXX_BITFIELD_MEMBER(1, 1, single, raw);           // only support 0
      CXX_BITFIELD_MEMBER(2, 2, address_interval, raw); // only support 0
      CXX_BITFIELD_MEMBER(3, 3, level_triggered_mode, raw); // ignore
      CXX_BITFIELD_MEMBER(4, 4, init, raw);
    };

    struct ICW4
    {
      l4_uint8_t raw;

      CXX_BITFIELD_MEMBER(0, 0, upm, raw); // 8086 mode, only one supported
      /**
       * Note from 8259a manual:
       * 8259As with a copyright date of 1985 or later will operate in the AEOI
       * mode as a master or a slave.
       * In AEOI mode interrupts are acked on delivery.
       */
      CXX_BITFIELD_MEMBER(1, 1, aeoi, raw);
      CXX_BITFIELD_MEMBER(2, 2, buffer_master, raw);
      CXX_BITFIELD_MEMBER(3, 3, buffer_mode, raw);
      CXX_BITFIELD_MEMBER(3, 3, sfnm, raw); // One iff special fully nested mode.
    };

    struct OCW2
    {
      l4_uint8_t raw;

      CXX_BITFIELD_MEMBER(0, 2, irq, raw);
      CXX_BITFIELD_MEMBER(5, 5, eoi, raw);
      CXX_BITFIELD_MEMBER(6, 6, sl, raw);
    };

    struct OCW3
    {
      l4_uint8_t raw;

      CXX_BITFIELD_MEMBER(0, 0, ris, raw);
      CXX_BITFIELD_MEMBER(1, 1, rr, raw);
      CXX_BITFIELD_MEMBER(2, 2, poll, raw);
      CXX_BITFIELD_MEMBER(5, 5, smm, raw);
      CXX_BITFIELD_MEMBER(6, 6, esmm, raw);
    };

    // Selected IRR/ISR register by OCW3 for even port reads
    bool _read_isr = false;
    // Interrupt service register. Stores the Irq currently being serviced.
    l4_uint8_t _isr = 0;
    // Interrupt request register. Stores incoming Irq requesting to be
    // serviced.
    l4_uint8_t _irr = 0;
    // Interrupt mask register. Masks out interrupts.
    l4_uint8_t _imr = 0;

    // Needed to keep track of initialization sequence
    Init_words _expect = Init_words::ICW1;

    // Offset of interrupts
    l4_uint8_t _offset = 0;
    l4_uint8_t _slave_at = 0;

    struct ICW1 _icw1 {0}; // store to keep track of single mode and icw4
    struct ICW4 _icw4 {0}; // store to keep track of aeoi mode

    bool _is_master;
    Legacy_pic *_pic;

  public:
    Chip(bool master, Legacy_pic *pic) : _is_master(master), _pic(pic)
    {
      _icw4.aeoi() = 1;
    }

    char const *dev_name() const override
    { return "PIC"; }

    /// Check interrupt mask/in-service and return the IRQ number with offset.
    int trigger(unsigned irq)
    {
      if (_offset == 0)
        return -1;

      unsigned irq_bit = 1U << irq;

      if (_isr || _imr & irq_bit)
        {
          _irr |= irq_bit;
          return -1;
        }
      else
        {
          if (!_icw4.aeoi())
            _isr |= irq_bit;
          _irr &= ~irq_bit;
          return _offset + irq;
        }
    }

  public:
    /// Handle read accesses on the PICs command and data ports.
    void io_in(unsigned port, Vmm::Mem_access::Width width, l4_uint32_t *value)
      override
    {
      *value = -1U;

      if (width != Vmm::Mem_access::Width::Wd8)
        return;

      switch (port)
        {
        case Cmd_port:
          *value = _read_isr ? _isr : _irr;
          break;

        case Data_port:
          *value = _imr;
          trace().printf("%s read mask 0x%x\n",
                         _is_master ? "Master:" : "Slave:", _imr);
          break;
        }

      trace().printf("%s port in: %s - 0x%x\n",
                     _is_master ? "Master:" : "Slave:",
                     port == 0 ? "cmd" : "data", *value);
    }

    /// Handle write accesses on the PICs command and data ports.
    void io_out(unsigned port, Vmm::Mem_access::Width width, l4_uint32_t value)
      override
    {
      if (width != Vmm::Mem_access::Width::Wd8)
        return;

      trace().printf("%s port out: %s - 0x%x\n",
                     _is_master ? "Master:" : "Slave:",
                     port == 0 ? "cmd" : "data", value);

      switch (port)
        {
        case Cmd_port:
          handle_command_write(value);
          break;

        case Data_port:
          handle_data_write(value);
          break;
        }
    }

  private:
    /// Return the number of the first pending interrupt or -1.
    int check_pending()
    {
      if (_isr || !(_irr & ~_imr))
        // we cannot issue new interrupts
        // if an interrupt is currently in service
        // or if all pending interrupts (in irr) are masked
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

    /**
     * EOI of last issued interrupt
     */
    void eoi(unsigned irq = 0)
    {
      if (!irq)
        _isr = 0;
      else
        _isr &= ~(1U << irq);

      if (_is_master)
        _pic->eoi(irq);
      else
        _pic->eoi(irq + 8);

      issue_next_interrupt();
    }

    void issue_next_interrupt()
    {
      int next_irq = check_pending();
      if (next_irq != -1)
        _pic->send_interrupt(next_irq + _offset);
    }


    /**
     * Reset to initial configuration
     */
    void reset()
    {
      _irr = _imr = _isr = 0;
      _expect = Init_words::ICW1;
      _offset = 0;
      _slave_at = 0;
      _icw1 = {0U};
      _icw4 = {0U};
      _icw4.aeoi() = 1;
    }

    void handle_command_write(l4_uint32_t command)
    {
      l4_uint8_t cmd = command;
      if (cmd & 0x10) // ICW1
        {
          // start initialization sequence
          reset();

          _icw1 = {cmd};
          if (_icw1.address_interval() || _icw1.single())
            warn().printf("Unsupported initialization value.\n");

          _expect = Init_words::ICW2;
          return;
        }

      if (_expect != Init_words::ICW1) // are we still in initialization?
        {
          warn().printf("%s: PIC is in initialization and guest wrote OCW (%x). Ignoring.\n",
                        _is_master ? "Master" : "Slave", cmd);
          return;
        }

      // handle OCWs
      if (cmd & 0x8)
        {
          struct OCW3 o{cmd};

          if (o.rr())
            {
              _read_isr = o.ris();
              return;
            }

          // ignore the rest
        }
      else // OCW2
        {
          struct OCW2 o{cmd};

          if (o.eoi())
            {
              if (o.sl())
                eoi(o.irq());
              else
                eoi();
            }

          // ignore the rest for now
        }
    }

    void handle_data_write(l4_uint32_t value)
    {
      if (_expect != Init_words::ICW1) // we are in initialization
        {
          switch (_expect)
            {
            case Init_words::ICW1: break; // avoid compiler warning

            case Init_words::ICW2:
              _offset = value;
              if (_icw1.single())
                {
                  if (_icw1.icw4())
                    _expect = Init_words::ICW4;
                  else
                    _expect = Init_words::ICW1; // initialization complete
                }
              else
                _expect = Init_words::ICW3;
              warn().printf("%s: Vector offset %u\n",
                            _is_master ? "MASTER" : "SLAVE", _offset);
              break;

            case Init_words::ICW3:
              _slave_at = value;
              if (_icw1.icw4())
                _expect = Init_words::ICW4;
              else
                {
                  _expect = Init_words::ICW1; // initialization complete
                  _read_isr = false;
                }
              break;

            case Init_words::ICW4:
              _icw4.raw = value;
              if (!_icw4.upm())
                warn().printf("Guest tries to set MCS-80 mode. Unsupported.\n");
              _expect = Init_words::ICW1; // initialization complete
              _read_isr = false;
              break;
            }
          return;
        }

      // OCW1
      _imr = value;
      // immediately inject pending irqs
      issue_next_interrupt();
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
    assert(irq < Num_irqs);

    int num = irq < 8 ? _master->trigger(irq) : _slave->trigger(irq - 8);
    // Do we need to set the _master line where the slave is wired to?
    if (num >= 32)
      send_interrupt(num);
  };

  void send_interrupt(int irq)
  {
    if (irq >= 32)
      {
        using namespace Vdev::Msix;

        Interrupt_request_compat addr(0ULL);
        // dest_id = 0, redirect_hint = 0, dest_mode = 0;
        addr.fixed() = Address_interrupt_prefix;

        Data_register_format data(0U);
        data.vector() = irq;
        data.delivery_mode() = Dm_extint;

        _distr->send(addr.raw, data.raw);
      }
  }

  void clear(unsigned) override {}

  void bind_irq_src_handler(unsigned irq, Gic::Irq_src_handler *handler) override
  {
    assert(irq < Num_irqs);
    if (handler && _sources[irq])
      throw L4::Runtime_error(-L4_EEXIST);

    _sources[irq] = handler;
  }

  Gic::Irq_src_handler *get_irq_src_handler(unsigned irq) const override
  {
    assert(irq < Num_irqs);
    return _sources[irq];
  }

  void eoi(unsigned irq)
  {
    assert(irq < Num_irqs);

    if (_sources[irq])
      _sources[irq]->eoi();
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
  Gic::Irq_src_handler *_sources[Num_irqs] = {};
};

} // namespace Vdev
