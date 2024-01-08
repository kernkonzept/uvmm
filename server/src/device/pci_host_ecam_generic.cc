/*
 * Copyright (C) 2019-2022 Kernkonzept GmbH.
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
 *    interrupt-map-mask = <0x1800 0x00 0x00 0x07>;
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
 *    // Optional: Map MSIs to GICv3 (if ITS emulation is enabled)
 *    // msi-map = <0x0 &its 0x0 0x10000>;
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
#include "pci_bus_cfg_ecam.h"
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
  public Device
{
public:
  explicit Pci_host_ecam_generic(Interrupt_map const &irq_map,
                                 unsigned char bus_num,
                                 Device_lookup *devs,
                                 Dt_node const &node,
                                 cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl)
  : Pci_host_bridge(devs, node, bus_num, msix_ctrl),
    _irq_map(irq_map)
  {
    header()->vendor_id = 0x1b36;        // PCI vendor id Redhat
    header()->device_id = 0x0008;        // PCI device id Redhat PCIe host
    header()->subsystem_vendor = 0x1af4; // PCI sub vendor id Redhat Qumranet (QEMU)
    header()->subsystem_id = 0x1100;     // PCI sub device id QEMU
    header()->classcode[1] = Pci_subclass_code_host;
    header()->classcode[2] = Pci_class_code_bridge_device;

    setup_devices();
  }

protected:
  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned) override
  {
    assert(false); // Must not be called. No BARs set up.
    return nullptr;
  }

  cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned) override
  {
    assert(false); // Must not be called. No BARs set up.
    return nullptr;
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
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCIe ctl"); }

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

  /**
   * Parse the MSI map and ensure that it describes an identity mapping targeted
   * at a single MSI controller.
   *
   * The purpose of the MSI map is to map devices via their Requester ID
   * (Bus number, Device number and Function number) to an MSI controller,
   * optionally applying an offset to the Requester ID.
   *
   * For now we only support the simple case, where the map contains one entry
   * that identity maps all requester IDs to a single MSI controller.
   */
  void parse_msi_map(Dt_node const &node)
  {
    int sz;
    fdt32_t const *map = node.get_prop<fdt32_t>("msi-map", &sz);
    if (!map)
      // In the absence of an msi-map assume identity mapping of Requester IDs.
      return;

    if (sz != 4)
      L4Re::chksys(-L4_EINVAL, "msi-map must have exactly one entry.");

    unsigned rid_base = cpu_to_fdt32(map[0]);
    unsigned msi_base = cpu_to_fdt32(map[2]);
    if (rid_base != 0 || msi_base != 0)
      L4Re::chksys(-L4_EINVAL,
                   "msi-map must describe a zero-based identity mapping.");
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

    parse_msi_map(node);

    cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl;
    // MSI controller is optional
    Device_lookup::Mc_error res = devs->get_or_create_mc(node, &msix_ctrl);
    if (res != Device_lookup::Mc_ok && res != Device_lookup::Mc_e_no_msiparent)
      warn().printf(
        "PCIe host bridge %s refers to invalid MSI controller: %s\n",
        node.get_name(), Device_lookup::mc_err_str(res));

    unsigned char bus_start = 0, bus_end = 0;
    if (!parse_bus_range(node, &bus_start, &bus_end))
      {
        warn().printf(
          "Bus range invalid in device tree. Device not created.\n");
        return nullptr;
      }

    auto dev = make_device<Pci_host_ecam_generic>(irq_map, bus_start, devs,
                                                  node, msix_ctrl);

    auto ecam_cfg_connector = make_device<Pci_bus_cfg_ecam>(dev);
    devs->vmm()->register_mmio_device(ecam_cfg_connector,
                                      Vmm::Region_type::Virtual, node);

    info().printf("Created & registered the PCIe host bridge\n");
    return dev;
  }
}; // struct F

static F f;
static Device_type t = {"pci-host-ecam-generic", nullptr, &f};

} // namespace
