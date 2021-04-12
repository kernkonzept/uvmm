/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

/**
 * Device for emulating a generic PCIe host bridge.
 *
 * On device creation it will scan the vbus for any PCI devices and add them to
 * its internal representation. Please note that device ids will appear in
 * increasing order, as found on the vbus, to the guest. This needs to be
 * reflected in the device tree entries when referring to any devices.
 *
 * Also note that the bridge has some limitations:
 * - Only one bus (0) is supported
 * - Bridges as devices are not supported
 * - Interrupt sharing is not supported
 * - IO configuration space access is not supported
 *
 * A device tree entry needs to look like this:
 *
 *  pcie@10000000 {
 *    // Interrupt map for two devices
 *    interrupt-map-mask = <0x1000 0x00 0x00 0x07>;
 *    interrupt-map = < 0x800 0x00 0x00 0x01 &gic 0x0 0x04 0x04
 *                      0x800 0x00 0x00 0x02 &gic 0x0 0x05 0x04
 *                      0x800 0x00 0x00 0x03 &gic 0x0 0x06 0x04
 *                      0x800 0x00 0x00 0x04 &gic 0x0 0x07 0x04
 *                      0x1000 0x00 0x00 0x01 &gic 0x0 0x05 0x04
 *                      0x1000 0x00 0x00 0x02 &gic 0x0 0x06 0x04
 *                      0x1000 0x00 0x00 0x03 &gic 0x0 0x07 0x04
 *                      0x1000 0x00 0x00 0x04 &gic 0x0 0x08 0x04
 *                      >;
 *    #interrupt-cells = <0x01>;
 *    ranges = <0x1000000 0x00 0x00000000 0x00 0x3eff0000 0x00 0x00010000
 *              0x2000000 0x00 0x10000000 0x00 0x10000000 0x00 0x2eff0000
 *              0x3000000 0x10 0x00000000 0x10 0x00000000 0x01 0x00000000>;
 *    reg = <0x40 0x10000000 0x00 0x10000000>;
 *    bus-range = <0x00 0x00>;
 *    #address-cells = <0x03>;
 *    #size-cells = <0x02>;
 *    device_type = "pci";
 *    compatible = "pci-host-ecam-generic";
 *  };
 *
 * Note: If you don't want Linux to remap the bars add linux,pci-probe-only=<1>
 * to the /chosen node of your device tree.
 */

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>

#include "debug.h"
#include "device.h"
#include "device_factory.h"
#include "ds_mmio_mapper.h"
#include "irq.h"
#include "irq_dt.h"
#include "mem_types.h"
#include "pci_device.h"
#include "pci_host_bridge.h"

namespace {

using namespace Vmm;
using namespace Vdev;
using namespace Vdev::Pci;

/**
 * Internal interrupt map representation.
 *
 * The interrupt-map entry will be scanned once and this map will be used on
 * PCI device creation.
 */
struct Interrupt_map
{
  /**
   * Interrupt mapping for one specific device and all available pins.
   */
  struct Dev_mapping
  {
    /**
     * Interrupt - Interrupt controller pair.
     */
    struct Irq_target
    {
      int irq;                  /// Interrupt to map to
      cxx::Ref_ptr<Gic::Ic> ic; /// Interrupt controller to use
    };
    Irq_target targets[Pci_hdr_interrupt_pin_max];
  };
  l4_uint32_t dev_id_mask;                /// Mask for device id's
  l4_uint32_t pin_mask;                   /// Mask for interrupt pins
  std::map<l4_uint32_t, Dev_mapping> map; /// Device id - Interrupt map
};

class Pci_host_ecam_generic
: public Pci_host_bridge,
  public Virt_pci_device,
  public Device,
  public Vmm::Mmio_device_t<Pci_host_ecam_generic>
{
public:
  /**
   * ECAM configuration space offset.
   *
   * This allows decoding of raw configuration space offsets into bus/device id's,
   * function number and register offsets.
   */
  struct Cfg_addr
  {
    l4_uint32_t raw = 0;
    CXX_BITFIELD_MEMBER(20, 31, bus, raw);  /// Bus id
    CXX_BITFIELD_MEMBER(15, 19, dev, raw);  /// Device id
    CXX_BITFIELD_MEMBER(12, 14, func, raw); /// Function number
    CXX_BITFIELD_MEMBER( 0, 11, reg, raw);  /// Register offset

    explicit Cfg_addr(l4_uint32_t r) : raw(r) {}
  };

  explicit Pci_host_ecam_generic(Interrupt_map const &irq_map, Device_lookup *devs)
  : Pci_host_bridge(devs),
    _irq_map(irq_map)
  {
    register_device(cxx::Ref_ptr<Pci_device>(this));
    iterate_pci_root_bus();

    header()->vendor_id = 0x1b36;        // PCI vendor id Redhat
    header()->device_id = 0x0008;        // PCI device id Redhat PCIe host
    header()->subsystem_vendor = 0x1af4; // PCI sub vendor id Redhat Qumranet (QEMU)
    header()->subsystem_id = 0x1100;     // PCI sub device id QEMU
    header()->classcode[1] = Pci_subclass_code_host;
    header()->classcode[2] = Pci_class_code_bridge_device;
  }

  /**
   * Read PCI configuration space.
   *
   * Device 0 is always the virtual host controller. Access to other regions is
   * forwarded to the corresponding device.
   */
  l4_uint32_t read(unsigned reg, char width, unsigned)
  {
    Cfg_addr cfg(reg);
    if (cfg.bus().get() > 0 || cfg.func().get() > 0)
      return -1U;
    return cfg_space_read(cfg.dev().get(), cfg.reg().get(), (Vmm::Mem_access::Width)width);
  }

  /**
   * Write PCI configuration space.
   *
   * Device 0 is always the virtual host controller. Access to other regions is
   * forwarded to the corresponding device.
   */
  void write(unsigned reg, char width, l4_uint32_t val, unsigned)
  {
    Cfg_addr cfg(reg);
    if (cfg.bus().get() > 0 || cfg.func().get() > 0)
      return;
    cfg_space_write(cfg.dev().get(), cfg.reg().get(), (Vmm::Mem_access::Width)width, val);
  }

private:
  /**
   * Return type 0 PCI header for the virtual PCIe host controller.
   */
  Pci_header::Type0 *header()
  { return get_header<Pci_header::Type0>(); }

  void setup_device_irq(Hw_pci_device *hw_dev)
  {
    l4vbus_device_t dinfo = hw_dev->dinfo;
    unsigned pin = 0;
    hw_dev->cfg_read(Pci_hdr_interrupt_pin_offset, &pin, Vmm::Mem_access::Width::Wd8);
    if (pin == 0) // No legacy interrupt messages enabled
      return;

    // Apply interrupt pin mask
    pin &= _irq_map.pin_mask;

    // Apply device id mask
    unsigned dev_id = (hw_dev->dev_id << 11) & _irq_map.dev_id_mask;
    if (!_irq_map.map.count(dev_id))
      L4Re::chksys(-L4_EINVAL, "PCI device not found in interrupt map.");

    // Query the corresponding irq/ic entry based on the device id and irq pin
    int map_irq = _irq_map.map.at(dev_id).targets[pin - 1].irq;
    cxx::Ref_ptr<Gic::Ic> ic = _irq_map.map.at(dev_id).targets[pin - 1].ic;

    // If the ic is empty this means it is unmanaged and we just skip the
    // setup.
    if (!ic)
      return;

    l4vbus_resource_t res[6];
    int io_irq = -1;
    for (unsigned i = 0; i < dinfo.num_resources; ++i)
      {
        if (hw_dev->dev.get_resource(i, &res[i]) != L4_EOK)
          continue;

        if (res[i].type == L4VBUS_RESOURCE_IRQ)
          {
            io_irq = res[i].start;
            break; // We only support one interrupt
          }
      }

    assert(io_irq != -1);

    // Create the io->guest irq mapping
    hw_dev->irq = cxx::make_ref_obj<Vdev::Irq_svr>(_vmm->registry(), _vbus->icu(),
                                                   io_irq, ic, map_irq);
    hw_dev->irq->eoi();
    info().printf("  IRQ mapping: %d -> %d\n", io_irq, map_irq);
  }

  void init_dev_resources(Hw_pci_device *hwdev) override
  {
    // Go through all resources of the PCI device and register them with the
    // memmap
    for (int i = 0; i < Pci_config_consts::Bar_num_max_type0; ++i)
      {
        if (hwdev->bars[i].type == Pci_cfg_bar::Type::Unused
            || hwdev->bars[i].type == Pci_cfg_bar::Type::IO)
          continue;

        Guest_addr addr(hwdev->bars[i].map_addr);
        l4_size_t size = hwdev->bars[i].size;
        switch (hwdev->bars[i].type)
          {
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

    setup_device_irq(hwdev);
  }

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCIe ctl"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCIe ctl"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCIe ctl"); }
private:
  Interrupt_map const _irq_map;
};

struct F : Factory
{
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCIe ctl"); }

  /*
   * Parses the interrupt map and create an internal representation.
   *
   * The map has to be parsed from the beginning to the end, because in theory
   * every entry could have a different amount of fields depending on the ic
   * used.
   *
   * An interrupt-map entry is defined as follow:
   * child id                   irq slot  ic phandle  irq spec
   * phys.hi phys.mid phys.low
   * 0x800   0x00     0x00      0x01      &gic        0x0 0x04 0x04
   *
   * The amount of cells to read is specified in the #xxxx-cells entries of the
   * corresponding node as follow:
   * child id: amount of #address-cells entries of pci node
   * irq slot: amount of #interrupt-cells entries of pci node
   * irq spec: amount of #interrupt-cells entries of ic node
   * There also may be a #address-cells entry for the ic, which we ignore.
   *
   * Before a device is looked up in the map the interrupt-map-mask needs to be
   * applied. The format is the same as for the child id and irq slot mappings.
   *
   * Every device can have up to Pci_hdr_interrupt_pin_max slot entries.
   */
  static void parse_interrupt_map(Interrupt_map *map, Device_lookup *devs,
                                  Dt_node const &node)
  {
    int map_addr_cells = node.get_cells_attrib("#address-cells");
    int map_int_cells = node.get_cells_attrib("#interrupt-cells");
    if (map_addr_cells != 3 || map_int_cells != 1)
      L4Re::chksys(-L4_EINVAL, "Cell attributes have wrong size.");

    int i = 0, sz;
    fdt32_t const *p = node.get_prop<fdt32_t>("interrupt-map-mask", &sz);
    if (!p || sz < map_addr_cells + map_int_cells)
      L4Re::chksys(-L4_EINVAL, "interrupt-map-mask attribute invalid.");
    map->dev_id_mask = cpu_to_fdt32(*p);
    p += map_addr_cells;
    map->pin_mask = cpu_to_fdt32(*p);

    p = node.get_prop<fdt32_t>("interrupt-map", &sz);
    i = 0;
    while (p && i < sz)
      {
        // Read child address
        unsigned dev = cpu_to_fdt32(p[i]);
        i += map_addr_cells;

        // Read child interrupt specifier
        unsigned irq_map = cpu_to_fdt32(p[i]);
        if (irq_map > Pci_hdr_interrupt_pin_max)
          L4Re::chksys(-L4_EINVAL, "Invalid value for interrupt pin.");
        i += map_int_cells;

        // Query dt node for ic
        Dt_node const pn = node.find_phandle(p[i++]);
        if (!pn.is_valid())
          L4Re::chksys(-L4_EINVAL, "Can't find node for phandle while "
                       "parsing interrupt-map");

        if (pn.has_prop("#address-cells")) // skip ic address cells
          i += pn.get_cells_attrib("#address-cells");

        // In case this is an unmanaged ic we have to skip its entries.
        if (!Vdev::Factory::is_vdev(pn))
          {
            if (pn.has_prop("#interrupt-cells")) // skip ic interrupt cells
              i += pn.get_cells_attrib("#interrupt-cells");

            Interrupt_map::Dev_mapping &m = map->map[dev];
            m.targets[irq_map - 1].irq = 0;
            m.targets[irq_map - 1].ic = nullptr;

            continue;
          }

        if (!pn.is_enabled())
          L4Re::chksys(-L4_EINVAL, "Interrupt parent is disabled.");

        cxx::Ref_ptr<Gic::Ic> ic = cxx::dynamic_pointer_cast<Gic::Ic>(
                Vdev::Factory::create_dev(devs, pn));
        if (!ic)
          L4Re::chksys(-L4_EINVAL, "Can't create device for interrupt parent.");

        int int_cells;
        int irq = ic->dt_get_interrupt(&p[i], sz-i, &int_cells);
        if (irq < 0)
          L4Re::chksys(-L4_EINVAL, "Can't translate interrupt.");
        i += int_cells;

        // Done parsing this entry; fetch or create map entry for this device
        Interrupt_map::Dev_mapping &m = map->map[dev];
        m.targets[irq_map - 1].irq = irq;
        m.targets[irq_map - 1].ic = ic;
      }
  }

  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    info().printf("Creating PCIe host bridge\n");

    if (!devs->vbus().get() || !devs->vbus()->available())
      {
        info().printf(
          "No vbus available. Device not created.\n");
        return nullptr;
      }

    // Parse the interrupt map once
    Interrupt_map irq_map;
    parse_interrupt_map(&irq_map, devs, node);

    auto dev = make_device<Pci_host_ecam_generic>(irq_map, devs);
    devs->vmm()->register_mmio_device(dev, Vmm::Region_type::Virtual, node);

    info().printf("Created & registered the PCIe host bridge\n");
    return dev;
  }
}; // struct F

static F f;
static Device_type t = {"pci-host-ecam-generic", nullptr, &f};

} // namespace
