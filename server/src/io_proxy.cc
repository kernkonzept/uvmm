/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <algorithm>

#include "device_factory.h"
#include "device_tree.h"
#include "guest.h"
#include "io_proxy.h"
#include "virt_bus.h"

namespace Vdev {

void
Io_proxy::init_device(Device_lookup const *devs, Dt_node const &self)
{
  if (!self.get_prop<fdt32_t>("interrupts", nullptr))
    return;

  auto irq_ctl = self.find_irq_parent();
  if (!irq_ctl.is_valid())
    L4Re::chksys(-L4_ENODEV, "No interupt handler found for virtio proxy.\n");

  // XXX need dynamic cast for Ref_ptr here
  auto *ic = dynamic_cast<Gic::Ic *>(devs->device_from_node(irq_ctl).get());

  if (!ic)
    L4Re::chksys(-L4_ENODEV, "No interupt handler found for IO passthrough.\n");

  int numint = std::min(ic->dt_get_num_interrupts(self), (int) _irqs.size());

  for (int i = 0; i < numint; ++i)
    {
      if (_irqs[i])
        {
          auto irq = ic->dt_get_interrupt(self, i);
          _irqs[i]->set_sink(ic, irq);
          ic->bind_irq_source(irq, _irqs[i]);
          _irqs[i]->eoi();
        }
    }
}

namespace {

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Vmm::Guest *vmm,
                              Vmm::Virt_bus *vbus,
                              Dt_node const &node)
  {
    // we can proxy memory and interrupts,
    // so look for resources that require one of the two
    if (!node.get_prop<fdt32_t>("reg", nullptr)
        && !node.get_prop<fdt32_t>("interrupts", nullptr))
    return nullptr;

    auto *vd = vbus->find_unassigned_dev(node);
    if (!vd)
      return nullptr;

    auto proxy = make_device<Io_proxy>(vd->io_dev);
    vd->proxy = proxy;

    for (unsigned i = 0; i < vd->dev_info.num_resources; ++i)
      {
        l4vbus_resource_t res;

        L4Re::chksys(vd->io_dev.get_resource(i, &res));

        char const *resname = reinterpret_cast<char const *>(&res.id);
        int id = resname[3] - '0';

        // MMIO memory: id must be 'regX' where X is the index into the
        //              device tree's 'reg' resource description
        if (res.type == L4VBUS_RESOURCE_MEM && !strncmp(resname, "reg", 3))
          {
            if (id < 0 || id > 9)
              {
                Err().printf("IO device '%.64s' has invalid mmio resource id. "
                             "Expected 'reg[0-9]', got '%.4s'.\n",
                             vd->dev_info.name, resname);
                L4Re::chksys(-L4_EINVAL);
              }

            Dbg().printf("Adding MMIO resource 0x%lx/0x%lx\n",
                         res.start, res.end);

            auto handler = Vdev::make_device<Ds_handler>(vbus->io_ds(), 0,
                                                         res.end - res.start + 1,
                                                         res.start);

            vmm->register_mmio_device(handler, node, id);
          }

        // Interrupts: id must be 'irqX' where X is the index into
        //             the device trees interrupts resource description
        if (res.type == L4VBUS_RESOURCE_IRQ &&
            !strncmp(resname, "irq", 3) && id >= 0 && id <= 9)
          {
            if (id < 0 || id > 9)
              {
                Err().printf("IO device '%.64s' has invalid irq resource id. "
                             "Expected 'irq[0-9]', got '%.4s'\n",
                             vd->dev_info.name, resname);
                L4Re::chksys(-L4_EINVAL);
              }

            auto svr = Vdev::make_device<Vdev::Irq_svr>();
            L4Re::chkcap(vmm->registry()->register_irq_obj(svr.get()));
            L4Re::chksys(vbus->icu()->bind(res.start, svr->obj_cap()));
            proxy->add_irq_source(id, svr);
          }
      }

    return proxy;
  }

  F() { pass_thru = this; }
};

static F f;

} // namespace

} // namespace
