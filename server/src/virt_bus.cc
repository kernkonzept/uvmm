/*
 * Copyright (C) 2016-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "device_tree.h"
#include "mmio_space_handler.h"
#include "io_port_handler.h"
#include "virt_bus.h"
#include "guest.h"
#include <l4/vbus/vbus_interfaces.h>

namespace Vmm {
void
Virt_bus::Irq_bitmap::dump_irqs()
{
  for (int i = 0; i < Num_irqs; ++i)
    {
      if (irq_present(i))
        Dbg().printf("Irq %d: %s\n", i, irq_bound(i) ? "bound" : "present");
    }
}

void
Virt_bus::scan_bus()
{
  L4vbus::Device io_dev;
  l4vbus_device_t dev_info;
  L4vbus::Device root = _bus->root();

  while (root.next_device(&io_dev, L4VBUS_MAX_DEPTH, &dev_info) == 0)
    {
      if (dev_info.type
          & (1 << L4VBUS_INTERFACE_PCI | 1 << L4VBUS_INTERFACE_PCIDEV))
        {
          Dbg(Dbg::Dev, Dbg::Trace, "VirtBus")
            .printf("scan_bus: skipping PCI device %s\n", dev_info.name);
          continue;
        }

      _devices.emplace_back(io_dev, dev_info);
    }
}

void
Virt_bus::collect_dev_resources(Virt_bus::Devinfo const &dev,
                                Vdev::Device_lookup const *devs)
{
  for (unsigned i = 0; i < dev.dev_info().num_resources; ++i)
    {
      l4vbus_resource_t res;

      L4Re::chksys(dev.io_dev().get_resource(i, &res),
                   "Cannot get resource in collect_resources");

      char const *resname = reinterpret_cast<char const *>(&res.id);

      if (res.type == L4VBUS_RESOURCE_MEM)
        {
          l4_size_t size = res.end - res.start + 1;
          auto region = Region::ss(Vmm::Guest_addr(res.start), size,
                                   Vmm::Region_type::Vbus);
          unsigned mmio_space_rw = L4VBUS_RESOURCE_F_MEM_MMIO_READ
                                 | L4VBUS_RESOURCE_F_MEM_MMIO_WRITE;
          bool is_mmio_space = res.flags & mmio_space_rw;
          Dbg(Dbg::Dev, Dbg::Info, "ioproxy")
            .printf("Adding MMIO %s %s.%.4s : [0x%lx - 0x%lx]\n",
                    is_mmio_space ? "space handler" : "resource",
                    dev.dev_info().name, resname, res.start, res.end);
          if (is_mmio_space)
            {
              if ((res.flags & mmio_space_rw) != mmio_space_rw)
                L4Re::chksys(-EINVAL,
                             "Only Mmio_space handlers for both reading and writing supported");

              auto mmiocap = L4::cap_reinterpret_cast<L4Re::Mmio_space>(_bus);
              auto handler =
                Vdev::make_device<Vdev::Mmio_space_handler>(mmiocap, 0, size,
                                                            res.start);
              devs->vmm()->add_mmio_device(region, handler);
            }
          else
            {
              l4_uint32_t rights = 0;
              if (res.flags & L4VBUS_RESOURCE_F_MEM_R)
                rights |= L4_FPAGE_RO;
              if (res.flags & L4VBUS_RESOURCE_F_MEM_W)
                rights |= L4_FPAGE_W;
              auto handler = Vdev::make_device<Ds_handler>(
                  cxx::make_ref_obj<Ds_manager>(std::string("Virt_bus: ") +
                                                  dev.dev_info().name,
                                                io_ds(),
                                                res.start, size,
                                                L4Re::Rm::Region_flags(rights)),
                  static_cast<L4_fpage_rights>(rights)
                );
              devs->vmm()->add_mmio_device(region, handler);
            }

        }
      else if (res.type == L4VBUS_RESOURCE_IRQ)
        {
          Dbg(Dbg::Dev, Dbg::Info, "ioproxy")
            .printf("Registering IRQ resource %s.%.4s : 0x%lx\n",
                    dev.dev_info().name, resname, res.start);
          _irqs.mark_irq_present(res.start);
        }
      else if (res.type == L4VBUS_RESOURCE_PORT)
        {
          Dbg(Dbg::Dev, Dbg::Info, "ioproxy")
            .printf("Registering IO Port resource %s.%.4s : 0x%lx - 0x%lx\n",
                    dev.dev_info().name, resname, res.start, res.end);
          auto region = Io_region::ss(res.start, res.end - res.start + 1,
                                      Vmm::Region_type::Vbus);
          L4Re::chksys(_bus->request_ioport(&res),
                       "Request IO port resource from vBus.");
          auto handler = Vdev::make_device<Vdev::Io_port_handler>(res.start);
          devs->vmm()->add_io_device(region, handler);
        }
    }
}

void
Virt_bus::collect_resources(Vdev::Device_lookup const *devs)
{
  for (auto &iodev : _devices)
    {
      if (iodev.allocated())
        continue;

      collect_dev_resources(iodev, devs);
    }
}

Virt_bus::Devinfo *
Virt_bus::find_unassigned_device_by_hid(char const *hid)
{
  L4vbus::Device vdev;
  while (_bus->root().device_by_hid(&vdev, hid) >= 0)
    {
      for (auto &iodev : _devices)
        if (   iodev.io_dev().dev_handle() == vdev.dev_handle()
            && !iodev.allocated())
          return &iodev;
    }

  return nullptr;
}

void Virt_bus::print_resource(l4vbus_resource_t const &res, char const *prefix)
{
  union
  {
    l4_uint32_t id32;
    char v[4];
  } id;
  id.id32 = res.id;

  const char *types[] = { "Invalid", "IRQ", "Mem", "Port",
                          "Bus", "GPIO", "DMA-Domain" };
  const char *rtype = "Unknown";
  if (res.type < cxx::array_size(types))
    rtype = types[res.type];


  Dbg(Dbg::Dev, Dbg::Info, "vbus").
    printf("%s%c%c%c%c: 0x%012lx-0x%012lx %s flags=%x\n",
           prefix,
           isprint(id.v[0]) ? id.v[0] : '_',
           isprint(id.v[1]) ? id.v[1] : '_',
           isprint(id.v[2]) ? id.v[2] : '_',
           isprint(id.v[3]) ? id.v[3] : '_',
           res.start, res.end, rtype, res.flags);
}

void Virt_bus::show_bus()
{
  Dbg d(Dbg::Dev, Dbg::Info, "vbus");
  if (d.is_active())
    {
      L4vbus::Device b(_bus, 0);
      L4vbus::Device dev;
      l4vbus_device_t dev_info;

      d.printf("Showing vbus contents:\n");
      while (b.next_device(&dev, L4VBUS_MAX_DEPTH, &dev_info) == 0)
        {
          d.printf("%s with %d resources\n",
                   dev_info.name, dev_info.num_resources);

          for (unsigned i = 0; i < dev_info.num_resources; ++i)
            {
              l4vbus_resource_t res;
              if (dev.get_resource(i, &res))
                continue;

              print_resource(res, " ");
            }
        }
    }
}

} // namespace
