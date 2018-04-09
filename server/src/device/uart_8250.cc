/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Phillip Raffeck <phillip.raffeck@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/bitfield>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/sys/cxx/ipc_epiface>
#include <l4/sys/vcon>

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "irq.h"
#include "mmio_device.h"

static Dbg warn(Dbg::Mmio, Dbg::Warn, "uart_8250");

namespace {

/**
 * Emulation of a 8250 serial device.
 *
 * Modem status and FIFO controls are ignored.
 *
 * To use this device e.g. under Linux add something like the following to the
 * device tree:
 *   uart8250@30018000 {
 *     compatible = "ns8250", "uart,8250";
 *     reg = <...>;
 *     clocks = <&sysclk>;
 *     clock-names = "apb_pclk";
 *   }
 *
 * "uart,8250" is the compatible string used by this device. "ns8250" is one of
 * the ones given in linux/Documentation/devicetree/bindings/serial/8250.txt.
 * Instead of specyfing an actual clock, a "clock-frequency" property with an
 * arbitrary value also suffices.
 */
class Uart_8250_mmio
: public Vmm::Mmio_device_t<Uart_8250_mmio>,
  public Vdev::Device,
  public L4::Irqep_t<Uart_8250_mmio>
{
  enum Regs
  {
    Rbr_thr_dll = 0,
    Ier_dlm     = 1,
    Iir         = 2,
    Lcr         = 3,
    Mcr         = 4,
    Lsr         = 5,
    Msr         = 6,
    Scr         = 7,
  };

  /// Interrupt Enable Register
  struct Ier_reg
  {
    l4_uint8_t raw;
    Ier_reg() : raw(0) {}
    explicit Ier_reg(l4_uint8_t v) : raw(v) {}

    /// Receive interrupt on error.
    CXX_BITFIELD_MEMBER(2, 2, rls, raw);
    /// Receive interrupt when data can be written.
    CXX_BITFIELD_MEMBER(1, 1, thre, raw);
    /// Receive interrupt when data is available.
    CXX_BITFIELD_MEMBER(0, 0, rda, raw);
  };

  /// Interrupt Identification Register
  struct Iir_reg
  {
    l4_uint8_t raw;
    Iir_reg() : raw(1) {}
    explicit Iir_reg(l4_uint8_t v) : raw(v) {}

    /// Interrupt IDs.
    enum Iir_id
    {
      Thre = 1, ///< Transmitter Holding Register is empty.
      Rda  = 2, ///< Receiver Data is availabe.
      Rls  = 3, ///< An error occurred.
    };

    /// Interrup ID.
    CXX_BITFIELD_MEMBER(1, 2, id, raw);
    /// 0, when interrupt is pending
    CXX_BITFIELD_MEMBER(0, 0, pending, raw);

    void set_data_irq()
    {
      id() = Rda;
      pending() = 0;
    }
    bool data_irq() const { return id() == Rda; }

    void set_error_irq()
    {
      id() = Rls;
      pending() = 0;
    }
    bool error_irq() const { return id() == Rls; }

    void set_write_irq()
    {
      id() = Thre;
      pending() = 0;
    }
    bool write_irq() const { return id() == Thre; }

    void clear() { raw = 1; }
  };

  /// Line Control Register
  struct Lcr_reg
  {
    l4_uint8_t raw;
    Lcr_reg() : raw(0) {}
    explicit Lcr_reg(l4_uint8_t v) : raw(v) {}

    /**
     * Divisor Latch Access Bit
     *
     * If 0, read/writes to registers 0 and 1 access RBR/THR/IER.
     * If 1, read/writes to registers 0 and 1 access DLL/DLM.
     */
    CXX_BITFIELD_MEMBER(7, 7, dlab, raw);
  };

  /// Line Status Register
  struct Lsr_reg
  {
    l4_uint8_t raw;
    Lsr_reg() : raw(0x60) {}
    explicit Lsr_reg(l4_uint8_t v) : raw(v) {}

    /// Break interrupt.
    CXX_BITFIELD_MEMBER(4, 4, bi, raw);
    /// Framing error.
    CXX_BITFIELD_MEMBER(3, 3, fe, raw);
    /// Parity error.
    CXX_BITFIELD_MEMBER(2, 2, pe, raw);
    /// Overrun error.
    CXX_BITFIELD_MEMBER(1, 1, oe, raw);
    /// Set, when data is available.
    CXX_BITFIELD_MEMBER(0, 0, dr, raw);

    void set_error()
    {
      bi() = 1;
      fe() = 1;
      pe() = 1;
      oe() = 1;
    }

    void clear_error()
    {
      bi() = 0;
      fe() = 0;
      pe() = 0;
      oe() = 0;
    }
  };

public:
  Uart_8250_mmio(L4::Cap<L4::Vcon> con, l4_uint64_t regshift, Gic::Ic *ic,
                 int irq)
  : _con(con), _regshift(regshift), _sink(ic, irq)
  {
    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        warn.printf("WARNING: Cannot set console attributes. "
                    "Output may not work as expected.\n");
        return;
      }

    attr.l_flags &= ~L4_VCON_ECHO;
    attr.o_flags &= ~L4_VCON_ONLRET;
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
  }

  void handle_irq()
  {
    if (_ier.rda())
      {
        _lsr.dr() = 1;
        _iir.set_data_irq();
        _sink.inject();
      }
  }

  L4::Cap<void> register_obj(L4::Registry_iface *registry)
  {
    auto ret = registry->register_irq_obj(this);
    _con->bind(0, L4Re::chkcap(ret, "Registering 8250 device"));

    return ret;
  }

  l4_uint32_t read(unsigned reg, char size, unsigned cpu_id)
  {
    l4_uint32_t ret = 0;
    switch (reg >> _regshift)
      {
      case Rbr_thr_dll:
        ret = _lcr.dlab() ? _dll : read_char();
        break;
      case Ier_dlm:
        ret = _lcr.dlab() ? _dlm : _ier.raw;
        break;
      case Iir:
        ret = _iir.raw;
        if (_iir.write_irq())
          {
            _iir.clear();
            _sink.ack();
          }
        break;
      case Lcr:
        ret = _lcr.raw;
        break;
      case Mcr:
        // Ignore modem control.
        break;
      case Lsr:
        ret = _lsr.raw;
        _lsr.clear_error();
        if (_iir.error_irq())
          {
            _iir.clear();
            _sink.ack();
          }
        break;
      case Msr:
        // Ignore modem status.
        break;
      case Scr:
        ret = _scr;
        break;
      default:
        warn.printf("Unhandled read: reg: %x size: %u cpu: %u\n",
                    reg, size, cpu_id);
        break;
      };

    return ret;
  }

  void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    switch (reg >> _regshift)
      {
      case Rbr_thr_dll:
        if (_lcr.dlab())
          _dll = value;
        else
          write_char((char)value);
        break;
      case Ier_dlm:
        if (_lcr.dlab())
          _dlm = value;
        else
          _ier.raw = value;
        break;
      case Iir:
        // Used by 16550 as FCR. Ignore for now.
        break;
      case Lcr:
        _lcr.raw = value;
        break;
      case Mcr:
        // Ignore modem control.
        break;
      case Lsr:
        // LSR is intended for RO-operation. Just ignore writes.
        break;
      case Msr:
        // Ignore modem status.
        break;
      case Scr:
        _scr = value;
        break;
      default:
        warn.printf("Unhandled write: reg: %x value: %x size: %u cpu: %u\n",
                    reg, value, size, cpu_id);
        break;
      };
  }

private:
  l4_uint32_t read_char()
  {
    int err;
    char buf;

    err = _con->read(&buf, 1);
    if (err < 0)
      {
        warn.printf("Error while reading from vcon: %d\n", err);
        _lsr.set_error();
        if (_ier.rls())
          {
            _iir.set_error_irq();
            _sink.inject();
          }
        return 0;
      }

    _sink.ack();
    if (err <= 1)
      {
        _iir.clear();
        _lsr.dr() = 0;
      }

    return buf;
  }

  void write_char(char c)
  {
    if (_iir.write_irq())
      {
        _iir.clear();
        _sink.ack();
      }
    _con->write(&c, 1);
    if (_ier.thre())
      {
        _iir.set_write_irq();
        _sink.inject();
      }
  }

  L4::Cap<L4::Vcon> _con;
  l4_uint64_t _regshift;
  Vmm::Irq_sink _sink;

  Ier_reg _ier;
  Iir_reg _iir;
  Lcr_reg _lcr;
  Lsr_reg _lsr;
  l4_uint8_t _scr;
  l4_uint8_t _dll;
  l4_uint8_t _dlm;

  Device *dev() { return static_cast<Device *>(this); }
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual 8250 console\n");
    L4::Cap<L4::Vcon> cap = L4Re::Env::env()->log();

    int regshift_size;
    fdt32_t const *regshift_prop = node.get_prop<fdt32_t>("reg-shift",
                                                          &regshift_size);
    l4_uint64_t regshift = 0;
    if (regshift_prop)
      regshift = node.get_prop_val(regshift_prop, regshift_size, true);

    int cap_name_len;
    char const *cap_name = node.get_prop<char>("l4vmm,8250cap", &cap_name_len);
    if (cap_name)
      {
        cap = L4Re::Env::env()->get_cap<L4::Vcon>(cap_name, cap_name_len);
        if (!cap)
          {
            warn.printf("'l4vmm,8250cap' property: capability %.*s is invalid.\n",
                        cap_name_len, cap_name);
            return nullptr;
          }
      }

    cxx::Ref_ptr<Gic::Ic> ic = devs->get_or_create_ic_dev(node, false);
    if (!ic)
      return nullptr;

    auto c = Vdev::make_device<Uart_8250_mmio>(cap, regshift,
                                               ic.get(),
                                               ic->dt_get_interrupt(node, 0));
    c->register_obj(devs->vmm()->registry());
    devs->vmm()->register_mmio_device(c, node);
    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "uart,8250", nullptr, &f };
