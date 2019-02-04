/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/re/error_helper>

#include "debug.h"
#include "device.h"
#include "pci_bus.h"
#include "device_factory.h"
#include "guest.h"
#include "ds_mmio_mapper.h"
#include "io_port_handler.h"

namespace Vdev {

void
Pci_bus_bridge::init_bus_range(Dt_node const &node)
{
  int sz;
  auto bus_range = node.get_prop<fdt32_t>("bus-range", &sz);
  if (sz != 2)
    {
      Err().printf("Bus range property of Pci_host_bridge has invalid size\n");
      return;
    }

  trace().printf("Init host bridge: Found 'bus-range' 0x%x - 0x%x\n",
                 fdt32_to_cpu(bus_range[0]), fdt32_to_cpu(bus_range[1]));

  auto *const hdr = header();
  hdr->secondary_bus_num = (l4_uint8_t)fdt32_to_cpu(bus_range[0]);
  hdr->subordinate_bus_num = (l4_uint8_t)fdt32_to_cpu(bus_range[1]);
}

void
Pci_bus_bridge::init_io_resources(Device_lookup *devs)
{
  auto vbus = devs->vbus();
  auto *vmm = devs->vmm();

  // create a MMIO/IO map device and entry for each PCI HW dev
  for (auto &hwdev : _pci_proxy_devs)
    {
      for (unsigned i = 0; i < hwdev.info.num_resources; ++i)
        {
          l4vbus_resource_t res;
          if (hwdev.dev.get_resource(i, &res))
            {
              info().printf(
                "Query resources for %s: Index %i from %i returned error\n",
                hwdev.info.name, i, hwdev.info.num_resources);
              continue;
            }

          trace().printf("found resource of %s: [0x%lx, 0x%lx], flags 0x%x, id "
                         "0x%x, type 0x%x \n",
                         hwdev.info.name, res.start, res.end, res.flags, res.id,
                         res.type);

          if (res.type == L4VBUS_RESOURCE_PORT)
            {
              L4Re::chksys(vbus->bus()->request_resource(&res));
              trace().printf("request resource: [0x%lx, 0x%lx]\n", res.start,
                             res.end);
              vmm->register_io_device(Io_region(res.start, res.end,
                                                Vmm::Region_type::Vbus),
                                      make_device<Io_port_handler>(res.start));
            }
          else if (res.type == L4VBUS_RESOURCE_MEM)
            {
              vmm->add_mmio_device(
                Region(Guest_addr(res.start), Guest_addr(res.end),
                       Vmm::Region_type::Vbus),
                make_device<Ds_handler>(vbus->bus(), 0,
                                        res.end - res.start + 1,
                                        res.start));
            }
          else
            trace().printf("Found unsupported resource type 0x%x\n", res.type);
        }
    }
}

}; // namespace Vdev

namespace {

using namespace Vdev;

struct F : Factory
{
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus"); }

  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    info().printf("Creating host bridge\n");

    if (!node.has_prop("bus-range"))
      {
        info().printf(
          "Bus range not specified in device tree. Device not created.\n");
        return nullptr;
      }

    auto dev = make_device<Pci_bus_bridge>(devs->vbus());
    dev->init_bus_range(node);
    dev->init_io_resources(devs);

    // If the Vbus provides a PCI bus with a host bridge, we don't need the
    // virtual one.
    if (!dev->is_io_pci_host_bridge_present())
      dev->register_device(dev);

    auto io_cfg_connector = make_device<Pci_bus_cfg_io>(dev);
    auto region = Vmm::Io_region(0xcf8, 0xcff, Vmm::Region_type::Virtual);
    devs->vmm()->register_io_device(region, io_cfg_connector);

    info().printf("Created & Registered the PCI host bridge\n");
    return dev;
  }
}; // struct F

static F f;
static Device_type t = {"virt-pci-bridge", nullptr, &f};

}; // namespace
