/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Phillip Raffeck <phillip.raffeck@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
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
#include "irq_dt.h"
#include "io_device.h"
#include "mmio_device.h"
#include "vcon_device.h"
#include "pm_device_if.h"

static Dbg warn(Dbg::Mmio, Dbg::Warn, "uart_8250");

namespace {

/**
 * Emulation of a 8250 serial device.
 *
 * Modem status and FIFO controls are ignored.
 *
 * On x86, to use this device e.g. under Linux add something like the
 * following to the device tree:
 * uart8250 {
 *       compatible = "ns8250", "uart,8250";
 *       reg = <0x0 0x0 0x0 0x0>;
 *       interrupt-parent = <&PIC>;
 *       interrupts = <4>;
 *       l4vmm,vcon_cap = "uart";
 *   };
 *
 * This emulates COM0 (irq = 4, ioports 0x3f8-0x400).
 *
 * On non-x86, e.g., on Arm, use the following in the device tree:
 *   uart8250@30018000 {
 *     compatible = "ns8250", "uart,8250";
 *     reg = <...>;
 *     clocks = <&sysclk>;
 *     clock-names = "apb_pclk";
 *     interrupts = <0 xxx 4>;
 *     l4vmm,vcon_cap = "uart";
 *   }
 *
 * "uart,8250" and "ns16550a" are the compatible string used by this
 * device. "ns8250" is one of the ones given in
 * linux/Documentation/devicetree/bindings/serial/8250.txt.
 * Instead of specyfing an actual clock, a "clock-frequency" property with an
 * arbitrary value also suffices.
 *
 * The 'uart' cap is optional. If it is not there output will be through
 * uvmm log cap.
 */

class Uart_8250_base
: public Vdev::Device,
  public Vcon_device,
  public L4::Irqep_t<Uart_8250_base>,
  public Vdev::Pm_device
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

    /// Interrupt ID.
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
    bool cleared() const { return raw == 1; }
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

    /// Set, when no transmission is running; clear by reading LSR.
    CXX_BITFIELD_MEMBER(6, 6, temt, raw);
    /// Set, when data can be written.
    CXX_BITFIELD_MEMBER(5, 5, thre, raw);
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

    void reset() { raw = 0x40; }
  };

public:
  Uart_8250_base(L4::Cap<L4::Vcon> con, l4_uint64_t regshift,
                 cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
  : Vcon_device(con), _regshift(regshift), _sink(ic, irq),
    _scr(0), _dll(0), _dlm(0)
  {
    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        warn.printf("WARNING: Cannot set console attributes. "
                    "Output may not work as expected.\n");
        return;
      }

    attr.set_raw();
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
  }

  void handle_irq()
  {
    _lsr.dr() = 1;
    if (!_iir.error_irq()) // error has higher prio. Don't overwrite.
      signal_readable();
  }

  l4_uint32_t read(unsigned reg, char size, unsigned)
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
            // If we got input while in error state, we need to tell the guest
            // about it.
            if (_lsr.dr())
              signal_readable();
            else
              signal_writeable();
          }
        break;
      case Msr:
        // Ignore modem status.
        break;
      case Scr:
        ret = _scr;
        break;
      default:
        warn.printf("Unhandled read: reg: %x size: %d\n", reg, size);
        break;
      };

    return ret;
  }

  void write(unsigned reg, char size, l4_uint32_t value, unsigned)
  {
    if (!_enabled)
      {
        attach_con_irq("UART 8250");
        _enabled = true;
      }

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
          {
            _ier.raw = value;

            if (_lsr.dr())
              signal_readable();
            else
              signal_writeable();
          }
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
        warn.printf("Unhandled write: reg: %x value: %x size: %u\n",
                    reg, value, size);
        break;
      };
  }

  void pm_suspend() override
  {
    flush_cons();
  }

  void pm_resume() override
  {
    reset();
  }

private:
  l4_uint32_t read_char()
  {
    _sink.ack(); // always ack the sink to allow new IRQs to pass-through it.

    int err;
    char buf = 0;

    err = _con->read(&buf, 1);
    if (err < 0)
      {
        warn.printf("Error while reading from vcon: %d\n", err);
        signal_error();
        return 0;
      }

    if (err <= 1)
      {
        _iir.clear();
        _lsr.dr() = 0;
      }

    return buf;
  }

  void write_char(char c)
  {
    _sink.ack(); // always ack the sink to allow new IRQs to pass-through it.

    if (_iir.write_irq())
      _iir.clear(); // if the IIR got overwritten, do not change it

    _con->write(&c, 1);

    // check if IIR shows read data available, it has higher priority.
    if (!_iir.cleared() && _iir.data_irq())
      {
        // IIR got overwritten between IIR read and THR write
        if (_ier.rda())
          _sink.inject();
      }
    else if (_iir.cleared())
      {
        // Nothing there to read, write has highest prio.
        signal_writeable();
      }
  }

  void signal_writeable()
  {
    _lsr.thre() = 1;
    if (!_ier.thre())
      return;

    _iir.set_write_irq();
    _sink.inject();
  }

  void signal_readable()
  {
    _lsr.dr() = 1;
    if (!_ier.rda())
      return;

    _iir.set_data_irq();
    _sink.inject();
  }

  void signal_error()
  {
    _lsr.set_error();
    if (!_ier.rls())
      return;

    _iir.set_error_irq();
    _sink.inject();
  }

  // Flush cons channel and drop the data to receive an IRQ on next input.
  void flush_cons()
  {
    int const sz = 100;
    char dummy[sz];
    while (_con->read(dummy, sz) > sz)
      ;

    // clear IRQ sink
    _sink.ack();
  }

  /**
   * Reset the UART state.
   *
   * Write reset values to the registers, flush the cons channel and set the
   * IRQ sink into cleared state.
   */
  void reset()
  {
    _ier.raw = 0;
    _iir.clear();
    _lsr.reset();
    _lcr.raw = 0;
    _scr = 0;
    _dll = 0;
    _dlm = 0;

    flush_cons();
  }

  l4_uint64_t _regshift;
  Vmm::Irq_sink _sink;
  bool _enabled = false;

  Ier_reg _ier;
  Iir_reg _iir;
  Lcr_reg _lcr;
  Lsr_reg _lsr;
  l4_uint8_t _scr;
  l4_uint8_t _dll;
  l4_uint8_t _dlm;

  Device *dev() { return static_cast<Device *>(this); }
};

class Uart_8250_mmio
: public Vmm::Mmio_device_t<Uart_8250_mmio>,
  public Uart_8250_base
{
public:
  Uart_8250_mmio(L4::Cap<L4::Vcon> con, l4_uint64_t regshift,
                 cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
  : Uart_8250_base(con, regshift, ic, irq)
  {}

  char const *dev_name() const override { return "Uart_8250_mmio"; }
};

class Uart_8250_io
: public Vmm::Io_device,
  public Uart_8250_base
{
public:
  Uart_8250_io(L4::Cap<L4::Vcon> con, cxx::Ref_ptr<Gic::Ic> const &ic, int irq)
  : Uart_8250_base(con, 0, ic, irq)
  {}

  char const *dev_name() const override
  { return "UART 8250"; }

  void io_in(unsigned reg, Vmm::Mem_access::Width width, l4_uint32_t *value) override
  {
    *value = read(reg, 1 << width, 0);
  }

  void io_out(unsigned reg, Vmm::Mem_access::Width width, l4_uint32_t value) override
  {
    write(reg, 1 << width, value, 0);
  }
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info, "uart_8250").printf("Create virtual 8250 console\n");

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,vcon_cap",
                                       L4Re::Env::env()->log());
    if (!cap)
      return nullptr;

    int regshift_size;
    fdt32_t const *regshift_prop = node.get_prop<fdt32_t>("reg-shift",
                                                          &regshift_size);
    l4_uint64_t regshift = 0;
    if (regshift_prop)
      regshift = node.get_prop_val(regshift_prop, regshift_size, true);


    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::chksys(-L4_EINVAL, "Uart 8250 requires a virtual interrupt controller");

    if (Vmm::Guest::Has_io_space) // Differentiate node types (MMIO or port-IO) here
      {
        auto region = Vmm::Io_region(0x3f8, 0x3ff, Vmm::Region_type::Virtual);
        auto c = Vdev::make_device<Uart_8250_io>(cap, it.ic(), it.irq());
        c->register_obj<Uart_8250_io>(devs->vmm()->registry());
        devs->vmm()->add_io_device(region, c);
        return c;
      }
    else
      {
        auto c = Vdev::make_device<Uart_8250_mmio>(cap, regshift, it.ic(),
                                                   it.irq());
        c->register_obj<Uart_8250_mmio>(devs->vmm()->registry());
        devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);
        return c;
      }
  }
};

static F f;
static Vdev::Device_type t1 = { "uart,8250", nullptr, &f };
static Vdev::Device_type t2 = { "ns16550a", nullptr, &f };

} // namespace
