/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/vbus/vbus>
#include <l4/re/error_helper>

#include "debug.h"
#include "device.h"
#include "pci_bus.h"
#include "device_factory.h"
#include "guest.h"
#include "ds_mmio_mapper.h"
#include "msi_memory.h"
#include "io_port_handler.h"
#include "ds_mmio_handling.h"
#include "msi_arch.h"
#include "msi_controller.h"

namespace Vdev { namespace Pci {

/**
 * Set up management of the MSI-X table page.
 */
static void
register_msix_table_page(Hw_pci_device const &hwdev, unsigned bir,
                         Vmm::Guest *vmm,
                         cxx::Ref_ptr<Vmm::Virt_bus> vbus,
                         cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl)
{
  assert(hwdev.has_msix);
  auto warn = Dbg(Dbg::Dev, Dbg::Warn, "PCI");
  unsigned max_msis = hwdev.msix_cap.ctrl.max_msis() + 1;

  l4_addr_t table_addr =
    hwdev.bars[bir].addr + hwdev.msix_cap.tbl.offset();
  l4_addr_t table_end = table_addr + max_msis * Msix::Entry_size - 1;

  l4_addr_t table_page = l4_trunc_page(table_addr);

  auto mem_mgr =
    cxx::make_ref_obj<Ds_access_mgr>(vbus->io_ds(), table_page, L4_PAGESIZE);

  l4_size_t pre_table_size = table_addr - table_page;
  if (pre_table_size > 0)
    {
      auto region = Region::ss(Guest_addr(table_page), pre_table_size,
                               Vmm::Region_type::Vbus);
      auto con = make_device<Mmio_ds_converter>(mem_mgr, 0);
      vmm->add_mmio_device(region, con);
      warn.printf("Register MMIO region before: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
    }

  l4_addr_t post_table = table_end + 1;
  l4_size_t post_table_size = table_page + L4_PAGESIZE - post_table;

  if (post_table_size > 0)
    {
      auto region = Region::ss(Guest_addr(post_table), post_table_size,
                               Vmm::Region_type::Vbus);
      auto con =
        make_device<Mmio_ds_converter>(mem_mgr, post_table - table_page);
      vmm->add_mmio_device(region, con);
      warn.printf("Register MMIO region after: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());
    }

  auto con =
    make_device<Mmio_ds_converter>(mem_mgr, table_addr - table_page);

  auto region = Region(Guest_addr(table_addr), Guest_addr(table_end),
                       Vmm::Region_type::Vbus);

  auto hdlr =
    Vdev::Msix::make_virt_msix_table(std::move(con),
                                     cxx::static_pointer_cast<Msi::Allocator>(
                                       vbus),
                                     vmm, hwdev.devfn, max_msis,
                                     msix_ctrl);

  warn.printf("Register MSI-X MMIO region: [0x%lx, 0x%lx]\n",
              region.start.get(), region.end.get());

  vmm->add_mmio_device(region, hdlr);
}

/**
 * Register non-MSI-X table pages as pass-through MMIO regions.
 *
 * \param bar         BAR containing the MSI-X table.
 * \param tbl_offset  Offset of the MSI-X table inside `bar`.
 * \param io_ds       Vbus' dataspace.
 * \param vmm         Guest pointer.
 */
static void
register_msix_bar(Pci_cfg_bar const *bar, l4_addr_t tbl_offset,
                  L4::Cap<L4Re::Dataspace> io_ds, Vmm::Guest *vmm)
{
  auto warn = Dbg(Dbg::Dev, Dbg::Warn, "PCI");

  l4_addr_t tbl_page_begin_rel = l4_trunc_page(tbl_offset);
  l4_addr_t tbl_page_size = L4_PAGESIZE;

  l4_addr_t before_area_begin = bar->addr;
  l4_addr_t before_area_size = tbl_page_begin_rel;

  l4_addr_t after_area_begin_rel = tbl_page_begin_rel + tbl_page_size;
  l4_addr_t after_area_begin = after_area_begin_rel + bar->addr;
  l4_addr_t after_area_size = bar->size - after_area_begin_rel;

  warn.printf("sizes before 0x%lx, after 0x%lx\n", before_area_size,
                after_area_size);

  if (before_area_size > 0)
    {
      auto region = Region::ss(Guest_addr(before_area_begin), before_area_size,
                               Vmm::Region_type::Vbus);

      warn.printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());

      vmm->add_mmio_device(region,
                           make_device<Ds_handler>(io_ds, 0, before_area_size,
                                                   region.start.get()));
    }

  if (after_area_size > 0)
    {
      auto region = Region::ss(Guest_addr(after_area_begin),
                               after_area_size, Vmm::Region_type::Vbus);

      warn.printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());

      vmm->add_mmio_device(region,
                           make_device<Ds_handler>(io_ds, 0, after_area_size,
                                                   region.start.get()));
    }
}

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
Pci_bus_bridge::init_dev_resources(Device_lookup *devs,
                                   cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl)
{
  auto vbus = devs->vbus();
  auto *vmm = devs->vmm();

  // Go through all resources of all PCI devices and register them with the
  // memmap or iomap.
  for (auto &hwdev : _hwpci_devs)
    {
      auto bir = hwdev.msix_cap.tbl.bir();
      assert(bir < Pci_config_consts::Bar_num_max_type0);

      if (hwdev.has_msix)
        {
          register_msix_table_page(hwdev, bir, vmm, vbus, msix_ctrl);

          register_msix_bar(&hwdev.bars[bir], hwdev.msix_cap.tbl.offset(),
                            vbus->io_ds(), vmm);
        }

      for (int i = 0; i < Pci_config_consts::Bar_num_max_type0; ++i)
        {
          if (i == bir || hwdev.bars[i].type == Pci_cfg_bar::Type::Unused)
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
            case Pci_cfg_bar::Type::MMIO64:
              {
                auto region = Region::ss(addr, size, Vmm::Region_type::Vbus);
                warn().printf("Register MMIO region: [0x%lx, 0x%lx]\n",
                              region.start.get(), region.end.get());
                vmm->add_mmio_device(region,
                                     make_device<Ds_handler>(vbus->io_ds(), 0,
                                                             size, addr.get()));
                break;
              }

            default: break;
            }
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
    dev->init_dev_resources(devs, devs->get_or_create_mc_dev(node));

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
