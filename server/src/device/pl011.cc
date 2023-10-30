/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Phillip Raffeck <phillip.raffeck@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cstring>

#include <l4/cxx/bitfield>
#include <l4/sys/cxx/ipc_epiface>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/sys/vcon>

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "irq.h"
#include "irq_dt.h"
#include "mmio_device.h"
#include "vcon_device.h"

namespace {

/**
 * Emulation of a PrimeCell UART pl011.
 *
 * Baud rate, FIFO setup and DMA setup are ignored.
 *
 * To use this device e.g. under Linux add something like the following to the
 * device tree:
 *   uart0: pl011_uart@30018000 {
 *    compatible = "arm,primecell", "arm,pl011";
 *    reg = <... 0x1000>;
 *    interrupts = <0 ... 4>;
 *    clocks = <&apb_dummy_pclk>;
 *    clock-names = "apb_pclk";
 *    l4vmm,vcon_cap = "log";
 *   };
 *
 *  apb_dummy_pclk: dummy_clk {
 *   compatible = "fixed-clock";
 *   #clock-cells = <0>;
 *   clock-frequency = <1000000>;
 *  };
 *
 * "arm,pl011" is the compatible string used by this device. "arm,primecell" is
 * one of those in linux/Documentation/devicetree/bindings/serial/pl011.yaml.
 * Although the linux documentation states that the clock properties are
 * optional, it's impossible to add the device, if these are missing (see add
 * and probe code in linux/drivers/amba/bus.c).
 *
 * You may add 'l4vmm,vcon_cap = "log";' to the pl011 node to use a
 * different vcon. Per default the standard uvmm console is used.
 *
 * For running this successfully in Linux (around 4.19 - 5.5 era), consider
 * the required settings:
 * - The size of the reg must be 0x1000
 * - The clock must be named "apb_pclk"
 * - The clock-frequency value of apb_dummy_pclk must be at least 1000000
 *
 * On the Linux command line, add "console=ttyAMA0" to use it as the
 * console.
 *
 * For earlycon (at least with arm64), add the following to the device tree
 * (typically in the very beginning of the device tree):
 *
 *   chosen {
 *     stdout-path = "serial0";
 *   };
 *   aliases {
 *     serial0 = &uart0;
 *   };
 *
 * And add "earlycon" to your Linux command line.
 */
class Pl011_mmio
: public Vmm::Mmio_device_t<Pl011_mmio>,
  public Vdev::Device,
  public Vcon_device,
  public L4::Irqep_t<Pl011_mmio>
{
public:
  enum Regs
  {
    DR        = 0x000,
    RSR_ECR   = 0x004,
    FR        = 0x018,
    IBRD      = 0x024,
    FBRD      = 0x028,
    LCR_H     = 0x02c,
    CR        = 0x030,
    IFLS      = 0x034,
    IMSC      = 0x038,
    RIS       = 0x03c,
    ICR       = 0x044,
    DMACR     = 0x048,
    PeriphID0 = 0xfe0,
    PeriphID1 = 0xfe4,
    PeriphID2 = 0xfe8,
    PeriphID3 = 0xfec,
    PCellID0  = 0xff0,
    PCellID1  = 0xff4,
    PCellID2  = 0xff8,
    PCellID3  = 0xffc,
  };

  struct Rsr_ecr_reg
  {
    // Reset value: 0x0
    l4_uint32_t raw;
    Rsr_ecr_reg() : raw(0) {}
    explicit Rsr_ecr_reg(l4_uint32_t v) : raw(v) {}

    CXX_BITFIELD_MEMBER(3, 3, oe, raw);
    CXX_BITFIELD_MEMBER(2, 2, be, raw);
    CXX_BITFIELD_MEMBER(1, 1, pe, raw);
    CXX_BITFIELD_MEMBER(0, 0, fe, raw);
  };

  struct Fr_reg
  {
    // Reset value: 0bX10010XXX
    // TXFE is ignored and only set here to adhere to the specification.
    l4_uint32_t raw;
    Fr_reg() : raw(0)
      {
        txfe().set(1);
        rxfe().set(1);
      }
    explicit Fr_reg(l4_uint32_t v) : raw(v) {}

    CXX_BITFIELD_MEMBER(7, 7, txfe, raw);
    CXX_BITFIELD_MEMBER(4, 4, rxfe, raw);
  };

  struct Cr_reg
  {
    // Reset value: 0x0300
    l4_uint32_t raw;
    Cr_reg() : raw(0)
      {
        rxe().set(1);
        txe().set(1);
      }
    explicit Cr_reg(l4_uint32_t v) : raw(v) {}

    CXX_BITFIELD_MEMBER(9, 9, rxe, raw);
    CXX_BITFIELD_MEMBER(8, 8, txe, raw);
    CXX_BITFIELD_MEMBER(0, 0, enable, raw);
  };

  struct Ris_reg
  {
    // Reset value: 0x00-
    l4_uint32_t raw;
    Ris_reg()  : raw(0) {}
    explicit Ris_reg(l4_uint32_t v) : raw(v) {}

    CXX_BITFIELD_MEMBER(4, 4, rx, raw);
  };

  Pl011_mmio(cxx::Ref_ptr<Gic::Ic> const &ic, int irq, L4::Cap<L4::Vcon> con)
  : Vcon_device(con), _sink(ic, irq)
  {
    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        Dbg(Dbg::Dev, Dbg::Warn, "pl011")
          .printf("WARNING: Cannot set console attributes. "
                  "Output may not work as expected.\n");
        return;
      }

    attr.set_raw();
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
  }

  void handle_irq()
  {
    _fr.rxfe().set(0);
    _ris.rx().set(1);
    _sink.inject();
  }

  l4_uint32_t read(unsigned reg, char size, unsigned cpu_id)
  {
    l4_uint32_t ret = 0;
    int err;
    char buf;
    switch (reg)
      {
      case DR:
        err = _con->read(&buf, 1);
        if (err < 0)
          {
            Dbg(Dbg::Dev, Dbg::Warn, "pl011")
              .printf("WARNING: Error while reading from vcon: %d\n", err);
            _rsr_ecr.raw = 0xf; // set error code
            ret |= (_rsr_ecr.raw & 0xf) << 8;
            break;
          }
        ret = buf;

        // bits 11-8 of DR are status flags
        ret |= (_rsr_ecr.raw & 0xf) << 8;

        _ris.rx().set(0);
        _sink.ack();
        if (err <= 1)
          _fr.rxfe().set(1);
        break;
      case RSR_ECR:
        ret = _rsr_ecr.raw;
        break;
      case FR:
        // Right now only the RXFE bit is considered. All other bits are
        // reported as 0, indicating the UART is not busy and we always accept
        // writes.
        ret = _fr.raw;
        break;
      case LCR_H:
        // Ignore FIFO (always use character mode) and word length (use 8 bits).
        ret = 0x60;
        break;
      case CR:
        ret = _cr.raw;
        break;
      case IMSC:
        ret = _imsc;
        break;
      case RIS:
        ret = _ris.raw;
        break;
      case PeriphID0:
        // Is also accessible as 32 bit register.
        if (size == 4)
          {
            ret = 0x341011;
            break;
          }

        ret = 0x11;
        break;
      case PeriphID1:
        ret = 0x10;
        break;
      case PeriphID2:
        ret = 0x34;
        break;
      case PeriphID3:
        ret = 0x0;
        break;
      case PCellID0:
        // Is also accessible as 32 bit register.
        if (size == 4)
          {
            ret = 0xb105f00d;
            break;
          }

        ret = 0x0d;
        break;
      case PCellID1:
        ret = 0xf0;
        break;
      case PCellID2:
        ret = 0x05;
        break;
      case PCellID3:
        ret = 0xb1;
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, "pl011")
          .printf("Unhandled read: register: %x size: %u cpu: %u\n",
                  reg, size, cpu_id);
        break;
      };

    return ret;
  }

  void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    char buf;
    switch (reg)
      {
      case DR:
        buf = (char)value;
        _con->write(&buf, 1);
        break;
      case RSR_ECR:
        _rsr_ecr.raw = 0x0;
        break;
      case IBRD:
      case FBRD:
        // Ignore baud rate.
        break;
      case LCR_H:
        // Ignore FIFO (always use character mode) and word length (use 8 bits).
        break;
      case CR:
        _cr.raw = value;
        if (_cr.enable() && _cr.rxe())
          attach_con_irq("pl011 device");
        break;
      case IFLS:
        // FIFO setup is ignored, so just ignore the interrupt trigger level.
        break;
      case IMSC:
        _imsc = value;
        break;
      case ICR:
        _ris.raw &= ~value;
        break;
      case DMACR:
        // Ignore DMA stuff.
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, "pl011")
          .printf("Unhandled write: register: %x value: %x size: %u cpu: %u\n",
                  reg, value, size, cpu_id);
        break;
      };
  }

  char const *dev_name() const override { return "Pl011_mmio"; }

private:
  Vmm::Irq_sink _sink;

  Rsr_ecr_reg _rsr_ecr;
  Fr_reg _fr;
  Cr_reg _cr;
  l4_uint32_t _imsc = 0;
  Ris_reg _ris;

  Device *dev() { return static_cast<Device *>(this); }
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual pl011 console\n");

    L4::Cap<L4::Vcon> cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,vcon_cap",
                                                    L4Re::Env::env()->log());
    if (!cap)
      return nullptr;

    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::chksys(-L4_EINVAL, "PL011 requires a virtual interrupt controller");

    auto c = Vdev::make_device<Pl011_mmio>(it.ic(), it.irq(), cap);
    c->register_obj<Pl011_mmio>(devs->vmm()->registry());
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);
    return c;
  }
};

}

static F f;
static Vdev::Device_type t1 = { "arm,pl011", nullptr, &f };
static Vdev::Device_type t2 = { "arm,sbsa-uart", nullptr, &f };
