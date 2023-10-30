/*
 * Copyright (C) 2018-2020 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>,
 *            Alexander Warg <alexander.warg@kernkonzept.com>,
 *            Frank Mehnert <frank.mehnert@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */


#include "device_factory.h"
#include "guest.h"
#include "irq.h"
#include "irq_dt.h"
#include "mmio_device.h"

namespace {

using namespace Vdev;

/**
 * Device for relaying L4 interrupts into the guest.
 *
 * A device tree entry needs to look like this:
 *
 *     virq {
 *       compatible = "l4vmm,virq-rcv";
 *       l4vmm,virqcap = "irqcap";
 *       interrupts = <0 140 4>;
 *     };
 *
 * `l4vmm,virqcap` is mandatory and needs to point to a capability
 * implementing an L4::Irq interface. If there is no capability with
 * the given name, then the device will be disabled.
 *
 * The device tree also must define exactly one interrupt in the
 * usual way.
 *
 * Interrupt relayed in this way do not need to be acknowledged by the
 * guest.
 */
class Irq_rcv
: public L4::Irqep_t<Irq_rcv>,
  public Device
{
public:
  Irq_rcv(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq) : _sink(ic, irq) {}

  void handle_irq()
  { _sink.inject(); }

private:
  // Use an edge sink since we do not need any EOI handling and do not want to
  // explicitly ACK interrupts on the Irq_*_sink
  Vmm::Irq_edge_sink _sink;
};


struct F_rcv : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto cap = Vdev::get_cap<L4::Irq>(node, "l4vmm,virqcap");
    if (!cap)
      return nullptr;

    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0)
      return nullptr;

    if (!it.ic_is_virt())
      L4Re::chksys(-L4_EINVAL, "Irq_rcv requires a virtual interrupt controller");

    auto c = make_device<Irq_rcv>(it.ic(), it.irq());
    auto res = devs->vmm()->registry()->register_obj(c.get(), cap);
    if (!res.is_valid())
      {
        Dbg(Dbg::Dev, Dbg::Warn, "Virq")
          .printf("Failed to register Virq on %s.l4vmm,virqcap: %s\n",
                  node.get_name(), l4sys_errtostr(res.cap()));
        L4Re::chkcap(res, "Register object", -L4_EINVAL); // does not return
      }
    return c;
  }
};

static F_rcv f_rcv;
static Device_type t_rcv = { "l4vmm,virq-rcv", nullptr, &f_rcv };

/**
 * Device for triggering L4 interrupts from the guest.
 *
 * A device tree entry needs to look like this:
 *
 *     virq@0x10000000 {
 *       compatible = "l4vmm,virq-snd";
 *       reg = <0x10000000 0x4>;
 *       l4vmm,virqcap = "irqcap";
 *     };
 *
 * `l4vmm,virqcap` is mandatory and needs to point to a capability
 * implementing an L4::Irq interface. If there is no capability with
 * the given name, then the device will be disabled.
 *
 * The interrupt is triggered by writing to any address in the region
 * specified by the first `reg` entry.
 */

class Irq_snd : public Device, public Vmm::Mmio_device_t<Irq_snd>
{
public:
  explicit Irq_snd(L4::Cap<L4::Irq> irq) : _irq(irq) {}

  void write(unsigned /*reg*/, char /*size*/, l4_uint64_t /*value*/, unsigned)
  {
    /* address does no matter */
    _irq->trigger();
  }

  l4_uint32_t read(unsigned /*reg*/, char /*size*/, unsigned /*cpu_id*/)
  {
    return 0;
  }

  char const *dev_name() const override { return "Irq_snd"; }

private:
  L4::Cap<L4::Irq> _irq;
};

struct F_snd : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto cap = Vdev::get_cap<L4::Irq>(node, "l4vmm,virqcap");
    if (!cap)
      return nullptr;

    auto c = make_device<Irq_snd>(cap);
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);
    return c;
  }
};

static F_snd f_snd;
static Device_type t_snd = { "l4vmm,virq-snd", nullptr, &f_snd };
}
