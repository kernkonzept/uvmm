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
#include "msi_memory.h"
#include "io_port_handler.h"

namespace Vdev { namespace Pci {

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

/**
 * Register non MSI-X table pages as pass-through MMIO regions.
 */
void Pci_bus_bridge::register_msix_bar_as_ds_handler(
  Pci_cfg_bar *bar, l4_addr_t tbl_offset, cxx::Ref_ptr<Vmm::Virt_bus> vbus,
  Vmm::Guest *vmm)
{
  l4_size_t before_msix_tbl_page = tbl_offset;
  l4_size_t after_msix_tbl_page = bar->size - (tbl_offset + 0x1000);

  warn().printf("sizes before 0x%lx, after 0x%lx\n", before_msix_tbl_page,
                after_msix_tbl_page);

  if (before_msix_tbl_page > 0)
    {
      auto region = Region::ss(Guest_addr(bar->addr), before_msix_tbl_page,
                               Vmm::Region_type::Vbus);
      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      vmm->add_mmio_device(region, make_device<Ds_handler>(vbus->io_ds(), 0,
                                                           before_msix_tbl_page,
                                                           region.start.get()));
    }

  if (after_msix_tbl_page > 0)
    {
      auto region = Region::ss(Guest_addr(bar->addr + tbl_offset + 0x1000),
                               after_msix_tbl_page, Vmm::Region_type::Vbus);
      warn().printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      vmm->add_mmio_device(region, make_device<Ds_handler>(vbus->io_ds(), 0,
                                                           after_msix_tbl_page,
                                                           region.start.get()));
    }
}

void Pci_bus_bridge::init_io_resources(Device_lookup *devs)
{
  auto vbus = devs->vbus();
  auto *vmm = devs->vmm();

  // System software enables, unmasks MSI-X. A device driver is not permitted
  // to do that.

  for (auto &hwdev : _hwpci_devs)
    {
      bool bars_used[5] = {false, false, false, false, false};

      for (int i = 0; i < 5; ++i)
        if (hwdev.bars[i].type != Pci_cfg_bar::Type::Unused)
          bars_used[i] = true;

      auto bir = hwdev.msix_cap.tbl.bir();
      assert(bir < 5);

      l4_addr_t msix_table =
        hwdev.bars[bir].addr + hwdev.msix_cap.tbl.offset();
      unsigned max_msis = hwdev.msix_cap.ctrl.max_msis() + 1;

      unsigned const src_id = 0x40000 | hwdev.devfn.value;

      auto hdlr = make_device<
        Msix::Table_memory>(vbus->io_ds(), msix_table,
                            cxx::static_pointer_cast<Msi::Allocator>(vbus),
                            vmm->registry(), max_msis,
                            src_id, vmm->apic_array());

      auto region = Region::ss(Guest_addr(msix_table),
                               l4_round_page(Msix::Entry_size * max_msis),
                               Vmm::Region_type::Vbus);

      warn().printf("Register MSI-X MMIO region: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
      vmm->add_mmio_device(region, hdlr);

      register_msix_bar_as_ds_handler(&hwdev.bars[bir],
                                      hwdev.msix_cap.tbl.offset(), vbus, vmm);

      bars_used[bir] = false;

      for (int i = 0; i < 5; ++i)
        {
          if (!bars_used[i])
            continue;

          Guest_addr addr(hwdev.bars[i].addr);
          l4_size_t size = hwdev.bars[i].size;

          switch (hwdev.bars[i].type)
            {
            case Pci_cfg_bar::Type::IO:
              {
                auto region =
                  Io_region::ss(addr.get(), size, Vmm::Region_type::Vbus);
                l4vbus_resource_t res;
                res.type = L4VBUS_RESOURCE_PORT;
                res.start = region.start;
                res.end = region.end;
                res.provider = 0;
                res.id = 0;
                L4Re::chksys(vbus->bus()->request_ioport(&res),
                             "Request IO port resource from vBus.");
                warn().printf("Register IO region: [0x%lx, 0x%lx]\n",
                              region.start, region.end);
                vmm->register_io_device(region, make_device<Io_port_handler>(
                                                  addr.get()));
                break;
              }

            case Pci_cfg_bar::Type::MMIO32:
              {
                auto region = Region::ss(addr, size, Vmm::Region_type::Vbus);
                warn().printf("Register MMIO region: [0x%lx, 0x%lx]\n",
                              region.start.get(), region.end.get());
                vmm->add_mmio_device(region,
                                     make_device<Ds_handler>(vbus->io_ds(), 0,
                                                             size, addr.get()));
                break;
              }

            case Pci_cfg_bar::Type::MMIO64: break;
            default: break;
            }

          bars_used[i] = false;
        }
    }
}

} } // namespace Vdev::Pci

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

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

} // namespace
