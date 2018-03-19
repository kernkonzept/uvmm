/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cstring>

#include "device_tree.h"
#include "virt_bus.h"
#include "guest.h"

namespace Vmm {
void
Virt_bus::Irq_bitmap::dump_irqs()
{
  for (int i = 0; i < Num_irqs; ++i)
    {
      if (irq_present(i))
        printf("Irq %d: %s\n", i, irq_bound(i) ? "bound" : "present");
    }
}

void
Virt_bus::scan_bus()
{
  L4vbus::Device root = _bus->root();
  Devinfo info;

  while (root.next_device(&info.io_dev, L4VBUS_MAX_DEPTH, &info.dev_info) == 0)
    _devices.push_back(info);
}

void
Virt_bus::collect_dev_resources(Virt_bus::Devinfo const &dev,
                                Vdev::Device_lookup const *devs)
{
  for (unsigned i = 0; i < dev.dev_info.num_resources; ++i)
    {
      l4vbus_resource_t res;

      L4Re::chksys(dev.io_dev.get_resource(i, &res),
                   "Cannot get resource in collect_resources");

      char const *resname = reinterpret_cast<char const *>(&res.id);

      if (res.type == L4VBUS_RESOURCE_MEM)
        {
          Dbg(Dbg::Dev, Dbg::Info, "ioproxy")
            .printf("Adding MMIO resource %s.%.4s : [0x%lx - 0x%lx]\n",
                    dev.dev_info.name, resname, res.start, res.end);

          l4_size_t size = res.end - res.start + 1;
          auto handler = Vdev::make_device<Ds_handler>(io_ds(), 0, size,
                                                       res.start);

          devs->vmm()->add_mmio_device(Region::ss(res.start, size), handler);
        }
      else if (res.type == L4VBUS_RESOURCE_IRQ)
        {
          Dbg(Dbg::Dev, Dbg::Info, "ioproxy")
            .printf("Registering IRQ resource %s.%.4s : 0x%lx\n",
                    dev.dev_info.name, resname, res.start);
          _irqs.mark_irq_present(res.start);
        }
    }
}

void
Virt_bus::collect_resources(Vdev::Device_lookup const *devs)
{
  for (auto &iodev : _devices)
    {
      if (iodev.proxy)
        continue;

      collect_dev_resources(iodev, devs);
    }
}

} // namespace
