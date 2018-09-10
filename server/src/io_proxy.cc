/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "device_factory.h"
#include "device_tree.h"
#include "guest.h"
#include "irq_dt.h"
#include "io_proxy.h"
#include "virt_bus.h"

static Dbg info(Dbg::Dev, Dbg::Info, "ioproxy");
static Dbg warn(Dbg::Dev, Dbg::Warn, "ioproxy");

namespace {

  void
  bind_irq(Vmm::Guest *vmm, Vmm::Virt_bus *vbus, Gic::Ic *ic,
           unsigned dt_irq, unsigned io_irq, char const *dev_name)
  {
    info.printf("IO device '%s' - registering irq 0x%x -> 0x%x\n",
                dev_name, io_irq, dt_irq);
    if (!ic->get_irq_source(dt_irq))
      {
        auto irq_svr = Vdev::make_device<Vdev::Irq_svr>(io_irq);

        L4Re::chkcap(vmm->registry()->register_irq_obj(irq_svr.get()),
                     "Invalid capability");

        // We have a 1:1 association, so if the irq is not bound yet we
        // should be able to bind the icu irq
        L4Re::chksys(vbus->icu()->bind(io_irq, irq_svr->obj_cap()),
                     "Cannot bind to IRQ");

        // Point irq_svr to ic:dt_irq for upstream events (like
        // interrupt delivery)
        irq_svr->set_sink(ic, dt_irq);

        // Point ic to irq_svr for downstream events (like eoi handling)
        ic->bind_irq_source(dt_irq, irq_svr);

        irq_svr->eoi();
        return;
      }

    warn.printf("IO device '%s': irq 0x%x -> 0x%x already registered\n",
                dev_name, io_irq, dt_irq);

    // Ensure we have the correct binding of the currently registered
    // source
    auto irq_source = ic->get_irq_source(dt_irq);
    auto other_svr = dynamic_cast<Vdev::Irq_svr const *>(irq_source.get());
    if (other_svr && (io_irq == other_svr->get_io_irq()))
      return;

    if (other_svr)
      Err().printf("bind_irq: ic:0x%x -> 0x%x -- "
                   "irq already bound to different io irq: 0x%x  \n",
                   dt_irq, io_irq, other_svr->get_io_irq());
    else
      Err().printf("ic:0x%x is bound to a different irq type\n",
                   dt_irq);
    throw L4::Runtime_error(-L4_EEXIST);
  }

}


namespace Vdev {

// default set to false
static bool phys_dev_prepared;

void
Io_proxy::prepare_factory(Device_lookup const *devs)
{
  devs->vbus()->collect_resources(devs);
  phys_dev_prepared = true;
}

namespace {

struct F : Factory
{
  static bool check_regs(Device_lookup const *devs,
                         Dt_node const &node)
  {
    if (!node.has_prop("reg"))
      return true;

    auto vmm = devs->vmm();
    l4_uint64_t addr, size;
    for (int index = 0; /* no condition */ ; ++index)
      {
        int res = node.get_reg_val(index, &addr, &size);
        switch (res)
          {
          case 0:
            if (!vmm->mmio_region_valid(Vmm::Guest_addr(addr), size))
              return false;
            break;
          case -Dt_node::ERR_BAD_INDEX:
            // reached end of reg entries
            return true;
          case -Dt_node::ERR_NOT_TRANSLATABLE:
            // region not managed by us
            continue;
          case -Dt_node::ERR_RANGE:
            info.printf("Reg entry too large '%s'.reg[%d]\n",
                        node.get_name(), index);
            return false;
          default:
            Err().printf("Invalid reg entry '%s'.reg[%d]: %s\n",
                         node.get_name(), index, fdt_strerror(res));
            return false;
          }
      }
  }

  bool check_and_bind_irqs(Device_lookup *devs, Dt_node const &node)
  {
    if (!node.has_irqs())
      return true;

    // Check whether all IRQs are available
    auto vbus = devs->vbus().get();

    Irq_dt_iterator it(devs, node);
    do
      {
        if (it.next(devs) < 0)
          return false;

        // Check that the IRQ is available on the vbus when a
        // virtual interrupt handler needs to be connected.
        if (it.ic_is_virt() && ! vbus->irq_present(it.irq()))
          return false;
      }
    while (it.has_next());

    // Now bind the IRQs.
    it = Irq_dt_iterator(devs, node);
    do
      {
        it.next(devs);

        if (it.ic_is_virt())
          {
            int dt_irq = it.irq();
            bind_irq(devs->vmm(), vbus, it.ic().get(), dt_irq, dt_irq,
                     node.get_name());
            vbus->mark_irq_bound(dt_irq);
          }
      }
    while (it.has_next());

    return true;
  }

  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    if (!phys_dev_prepared)
      {
        Err().printf("%s: Io_proxy::create() invoked before prepare_factory()\n"
                     "\tprobably invalid device tree\n", node.get_name());
        return nullptr;
      }

    // Check mmio resources - mmio areas are already established
    if (!check_regs(devs, node))
      return nullptr;

    if (!check_and_bind_irqs(devs, node))
      return nullptr;

    L4vbus::Device io_dev;
    return make_device<Io_proxy>(io_dev);
  }

  F() { pass_thru = this; }
};

static F f;

} // namespace

} // namespace
