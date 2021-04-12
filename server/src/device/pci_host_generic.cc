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
#include "pci_host_bridge.h"
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
 * PCI bus emulation.
 *
 * The emulated host bridge handles the PCI bus transaction initialized by the
 * guest OS. Linux detects the virtual host bridge and queries the root bus for
 * devices present.
 * If hardware devices are supplied via Vbus, the virtio devices are merged
 * into Vbus' PCI root bus.
 */
class Pci_host_generic:
  public Pci_host_bridge,
  public Virt_pci_device,
  public Device
{
  Pci_header::Type1 *header()
  { return get_header<Pci_header::Type1>(); }

public:
  explicit Pci_host_generic(Device_lookup *devs,
                            cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl)
  : Pci_host_bridge(devs),
    _msix_ctrl(msix_ctrl)
  {
    register_device(cxx::Ref_ptr<Pci_device>(this));
    iterate_pci_root_bus();

    // Linux' x86 PCI_direct code sanity checks for a device with class code
    // PCI_CLASS_DISPLAY_VGA(0x0300) or PCI_CLASS_BRIDGE_HOST(0x00) or for a
    // device of vendor INTEL or COMPAQ.
    // see linux/arch/x86/pci/direct.c
    header()->classcode[2] = Pci_class_code_bridge_device;
    header()->classcode[1] = Pci_subclass_code_host;
    header()->header_type = 1; // PCI_TO_PCI_BRIDGE
    header()->command = Bus_master_bit | Io_space_bit;
  }

  void init_bus_range(Dt_node const &node);
  void init_dev_resources(Hw_pci_device *) override;

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI bus"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI bus"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus"); }

  cxx::Ref_ptr<Gic::Msix_controller> _msix_ctrl;
}; // class Pci_host_generic

/**
 * Interface to handle IO port access to the PCI configuration space and
 * translate it to an internal protocol.
 */
class Pci_bus_cfg_io : public Vmm::Io_device
{
  struct Config_address
  {
    l4_uint32_t raw = 0;
    CXX_BITFIELD_MEMBER(31, 31, enabled, raw);
    CXX_BITFIELD_MEMBER(24, 27, reghi, raw);
    CXX_BITFIELD_MEMBER(16, 23, bus, raw);
    CXX_BITFIELD_MEMBER(11, 15, dev, raw);
    CXX_BITFIELD_MEMBER( 8, 10, func, raw);
    CXX_BITFIELD_MEMBER( 2,  7, reglo, raw);
    CXX_BITFIELD_MEMBER( 0,  1, type, raw);

    unsigned reg() const
    {
      // the PCI standard requests the lowest two bits to be 0;
      return (static_cast<unsigned>(reghi()) << 8) | (reglo() << 2);
    }
  };
  Config_address _cfg_addr;
  cxx::Ref_ptr<Pci_host_generic> _bus;

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI bus io"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI bus io"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus io"); }

  enum
  {
    Pci_bus_config_address    = 0,
    Pci_bus_fwd_register      = 2,
    Pci_bus_config_mechanism  = 3,
    Pci_bus_config_data       = 4,
    Pci_bus_config_data_15_8  = 5,
    Pci_bus_config_data_31_16 = 6,
    Pci_bus_config_data_31_24 = 7,
  };

public:
  Pci_bus_cfg_io(cxx::Ref_ptr<Pci_host_generic> const &pci_bus) : _bus(pci_bus) {}

  void io_out(unsigned port, Vmm::Mem_access::Width width,
              l4_uint32_t value) override
  {
    using Vmm::Mem_access;
    trace().printf("OUT access @0x%x/%d => 0x%x\n", port, width, value);

    switch (port)
      {
      case Pci_bus_config_mechanism:
        if (width == Mem_access::Wd8)
          {
            // if 1 -> PCI conf mechanism 1
            // if 0 -> PCI conf mechanism 2 (deprecated 1992)
            // PCI v.3 does not support mechanism 2, hence ignore and return.
            // XXX Probing can be suppressed by adding 'pci=conf1' to the
            // cmdline
            return;
          }
        break;
      case Pci_bus_fwd_register:
        // identifies 1 of 256 possible PCI busses
        // used in deprecated PCI conf mechansim 2; only byte width access
        break;

      case Pci_bus_config_address: // Configuration Space Enable - CSE
        if (width == Mem_access::Wd32)
          {
            _cfg_addr.raw = value;
            return;
          }
        // non 32bit width access is normal IO transaction.
        break;

      case Pci_bus_config_data_31_24:
        // Falls through.
      case Pci_bus_config_data_15_8:
        if (width != Mem_access::Wd8)
          break;
        // Else falls through.
      case Pci_bus_config_data_31_16:
        if (width == Mem_access::Wd32)
          break;
        // Else falls through.
      case Pci_bus_config_data:
        {
          if (!_cfg_addr.enabled())
            return;

          unsigned reg = _cfg_addr.reg() + (port - Pci_bus_config_data);
          if (_cfg_addr.bus() > 0 || _cfg_addr.func() > 0)
            return;
          _bus->cfg_space_write(_cfg_addr.dev().get(), reg, width, value);
          return;
        }
      }

    trace().printf("Unhandled OUT access @0x%x/%d => 0x%x\n", port,
                   width, value);
  }

  void io_in(unsigned port, Vmm::Mem_access::Width width,
             l4_uint32_t *value) override
  {
    using Vmm::Mem_access;
    trace().printf("IN access to @0x%x/%d\n", port, width);

    *value = -1;

    switch (port)
      {
      case Pci_bus_fwd_register: // identifies 1 of 256 possible PCI busses
        break;

      case Pci_bus_config_address:
        if (width == Mem_access::Wd32)
          {
            *value = _cfg_addr.raw;
            trace().printf("IN access to PCI config space @0x%x/%d => 0x%x\n",
                           port, width, *value);
            return;
          }
        break;
      case Pci_bus_config_data_31_24:
        // Falls through.
      case Pci_bus_config_data_15_8:
        if (width != Mem_access::Wd8)
          break;
        // Else falls through.
      case Pci_bus_config_data_31_16:
        if (width == Mem_access::Wd32)
          break;
        // Else falls through.
      case Pci_bus_config_data:
        {
          if (!_cfg_addr.enabled())
            return;

          unsigned reg = _cfg_addr.reg() + (port - Pci_bus_config_data);
          if (_cfg_addr.bus() > 0 || _cfg_addr.func() > 0)
            {
              *value = ~0;
              return;
            }
          trace().printf("io_in: dev = %d\n", _cfg_addr.dev().get());
          assert(_bus != nullptr);
          *value = _bus->cfg_space_read(_cfg_addr.dev().get(),
                                        reg, width);
          trace().printf("IN access @0x%x/%d reg: 0x%x --> 0x%x\n", port, width,
                         reg, *value);
          return;
        }
      }
    trace().printf("Unhandled IN access @0x%x/%d\n", port, width);
  }
}; // Pci_bus_cfg_io

/**
 * Set up management of the MSI-X table page.
 */
static void
register_msix_table_page(Pci_host_bridge::Hw_pci_device *hwdev, unsigned bir,
                         Vmm::Guest *vmm,
                         cxx::Ref_ptr<Vmm::Virt_bus> vbus,
                         cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl)
{
  assert(hwdev);
  assert(hwdev->has_msix);
  auto warn = Dbg(Dbg::Dev, Dbg::Warn, "PCI");
  unsigned max_msis = hwdev->msix_cap.ctrl.max_msis() + 1;

  l4_addr_t table_addr =
    hwdev->bars[bir].map_addr + hwdev->msix_cap.tbl.offset().get();
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
                                     vmm, hwdev->src_id(), max_msis,
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

  l4_addr_t before_area_begin = bar->map_addr;
  l4_addr_t before_area_size = tbl_page_begin_rel;

  l4_addr_t after_area_begin_rel = tbl_page_begin_rel + tbl_page_size;
  l4_addr_t after_area_begin = after_area_begin_rel + bar->map_addr;
  l4_addr_t after_area_size = bar->size - after_area_begin_rel;

  warn.printf("sizes before 0x%lx, after 0x%lx\n", before_area_size,
                after_area_size);

  cxx::Ref_ptr<Vmm::Ds_manager> m;

  if (before_area_size || after_area_size)
    m = cxx::make_ref_obj<Vmm::Ds_manager>(io_ds, bar->map_addr, bar->size);

  if (before_area_size > 0)
    {
      auto region = Region::ss(Guest_addr(before_area_begin), before_area_size,
                               Vmm::Region_type::Vbus);

      warn.printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());

      vmm->add_mmio_device(region, make_device<Ds_handler>(m, 0));
    }

  if (after_area_size > 0)
    {
      auto region = Region::ss(Guest_addr(after_area_begin),
                               after_area_size, Vmm::Region_type::Vbus);

      warn.printf("Register MMIO region in MSI-X bar: [0x%lx, 0x%lx]\n",
                    region.start.get(), region.end.get());

      vmm->add_mmio_device(region,
                           make_device<Ds_handler>(m, after_area_begin_rel));
    }
}

void
Pci_host_generic::init_bus_range(Dt_node const &node)
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
Pci_host_generic::init_dev_resources(Hw_pci_device *hwdev)
{
  // Go through all resources of the PCI device and register them with the
  // memmap or iomap.
  int bir = Pci_config_consts::Bar_num_max_type0;
  if (hwdev->has_msix)
    {
      bir = hwdev->msix_cap.tbl.bir();
      assert(bir < Pci_config_consts::Bar_num_max_type0);

      register_msix_table_page(hwdev, bir, _vmm, _vbus, _msix_ctrl);

      register_msix_bar(&hwdev->bars[bir], hwdev->msix_cap.tbl.offset(),
                        _vbus->io_ds(), _vmm);
    }

  for (int i = 0; i < Pci_config_consts::Bar_num_max_type0; ++i)
    {
      if (i == bir || hwdev->bars[i].type == Pci_cfg_bar::Type::Unused)
        continue;

      Guest_addr addr(hwdev->bars[i].map_addr);
      l4_size_t size = hwdev->bars[i].size;
      switch (hwdev->bars[i].type)
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
            L4Re::chksys(_vbus->bus()->request_ioport(&res),
                         "Request IO port resource from vBus.");
            warn().printf("Register IO region: [0x%lx, 0x%lx]\n",
                          region.start, region.end);
            _vmm->register_io_device(region, make_device<Io_port_handler>(addr.get()));
            break;
          }

        case Pci_cfg_bar::Type::MMIO32:
        case Pci_cfg_bar::Type::MMIO64:
          {
            auto region = Region::ss(addr, size, Vmm::Region_type::Vbus,
                                     Vmm::Region_flags::Moveable);
            // Mark region as moveable so it can't be merged
            warn().printf("Register MMIO region: [0x%lx, 0x%lx]\n",
                          region.start.get(), region.end.get());
            auto m = cxx::make_ref_obj<Ds_manager>(_vbus->io_ds(),
                                                   hwdev->bars[i].map_addr, size);
            _vmm->add_mmio_device(region, make_device<Ds_handler>(m));
            break;
          }

        default: break;
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

    auto dev = make_device<Pci_host_generic>(devs, devs->get_or_create_mc_dev(node));
    dev->init_bus_range(node);

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
