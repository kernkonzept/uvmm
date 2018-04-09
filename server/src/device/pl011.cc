/*
 * Copyright (C) 2017 Kernkonzept GmbH.
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
#include "mmio_device.h"

namespace {

/**
 * Emulation of a PrimeCell UART pl011.
 *
 * Baud rate, FIFO setup and DMA setup are ignored.
 *
 * To use this device e.g. under Linux add something like the following to the
 * device tree:
 *   pl011_uart@30018000 {
 *    compatible = "arm,primecell", "arm,pl011";
 *    reg = <...>;
 *    clocks = <&sysclk>;
 *    clock-names = "apb_pclk";
 *   };
 *
 * "arm,pl011" is the compatible string used by this device. "arm,primecell" is
 * one of those in linux/Documentation/devicetree/bindings/serial/pl011.txt.
 * Although the linux documentation states that the clock properties are
 * optional, it's impossible to add the device, if these are missing (see add
 * and probe code in linux/drivers/amba/bus.c).
 */
class Pl011_mmio
: public Vmm::Mmio_device_t<Pl011_mmio>,
  public Vdev::Device,
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
  };

  struct Ris_reg
  {
    // Reset value: 0x00-
    l4_uint32_t raw;
    Ris_reg()  : raw(0) {}
    explicit Ris_reg(l4_uint32_t v) : raw(v) {}

    CXX_BITFIELD_MEMBER(4, 4, rx, raw);
  };

  explicit Pl011_mmio(Gic::Ic *ic, int irq,
                      L4::Cap<L4::Vcon> con = L4Re::Env::env()->log())
  : _con(con), _sink(ic, irq)
  {
    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        Dbg(Dbg::Dev, Dbg::Warn, "pl011")
          .printf("WARNING: Cannot set console attributes. "
                  "Output may not work as expected.\n");
        return;
      }

    attr.l_flags &= ~L4_VCON_ECHO;
    attr.o_flags &= ~L4_VCON_ONLRET;
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
  }

  void handle_irq()
  {
    _fr.rxfe().set(0);
    _ris.rx().set(1);
    _sink.inject();
  }

  L4::Cap<void> register_obj(L4::Registry_iface *registry)
  {
    auto ret = registry->register_irq_obj(this);
    _con->bind(0, L4Re::chkcap(ret, "Registering pl011 device"));

    return ret;
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
        // Ignore modem status etc. and just report the bits back to the client.
        _cr.raw = value;
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

private:
  L4::Cap<L4::Vcon> _con;
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
    int cap_name_len;
    L4::Cap<L4::Vcon> cap = L4Re::Env::env()->log();

    char const *cap_name = node.get_prop<char>("l4vmm,pl011cap", &cap_name_len);
    if (cap_name)
      {
        cap = L4Re::Env::env()->get_cap<L4::Vcon>(cap_name, cap_name_len);
        if (!cap)
          {
            Dbg(Dbg::Dev, Dbg::Warn, "pl011")
              .printf("'l4vmm,pl011cap' property: capability %.*s is invalid.\n",
                      cap_name_len, cap_name);
            return nullptr;
          }
      }

    cxx::Ref_ptr<Gic::Ic> ic = devs->get_or_create_ic_dev(node, false);
    if (!ic)
      return nullptr;

    auto c = Vdev::make_device<Pl011_mmio>(ic.get(),
                                           ic->dt_get_interrupt(node, 0), cap);
    c->register_obj(devs->vmm()->registry());
    devs->vmm()->register_mmio_device(c, node);
    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "arm,pl011", nullptr, &f };
