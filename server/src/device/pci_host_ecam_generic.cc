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
#include "guest.h"
#include "ds_mmio_mapper.h"
#include "irq.h"
#include "irq_dt.h"
#include "irq_svr.h"
#include "pci_device.h"
#include "virt_bus.h"

namespace {

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
: public Pci_dev,
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
  : _vmm(devs->vmm())
  {
    header()->vendor_id = 0x1b36;        // PCI vendor id Redhat
    header()->device_id = 0x0008;        // PCI device id Redhat PCIe host
    header()->subsystem_vendor = 0x1af4; // PCI sub vendor id Redhat Qumranet (QEMU)
    header()->subsystem_id = 0x1100;     // PCI sub device id QEMU
    header()->classcode[1] = Pci_subclass_code_host;
    header()->classcode[2] = Pci_class_code_bridge_device;

    iterate_pci_root_bus(devs->vbus(), irq_map);
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
    if (cfg.bus() > 0 || cfg.dev() > _devices.size() || cfg.func() > 0)
      return -1u;

    l4_uint32_t val = 0;
    if (cfg.dev() == 0)
      // Virtual bridge
      cfg_read(cfg.reg(), &val, (Vmm::Mem_access::Width)width);
    else
      // Pass-through to device
      device(cfg).cfg_read(cfg.reg(), &val, 8 << width);

    if (0)
      trace().printf("read cfg dev=%u reg=0x%x width=%d raw=0x%x val=0x%x\n",
                     cfg.dev().get(), cfg.reg().get(), (int)width, reg, val);

    return val;
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
    if (cfg.bus() > 0 || cfg.dev() > _devices.size() || cfg.func() > 0)
      return;

    if (cfg.dev() == 0)
      {
        // Virtual bridge
        // - no bar support
        // - no expansion ROM support
        if ((   cfg.reg() >= Pci_hdr_base_addr0_offset
             && cfg.reg() <= Pci_hdr_base_addr5_offset)
            || cfg.reg() == Pci_hdr_expansion_rom_offset)
          return;
        cfg_write(cfg.reg(), val, (Vmm::Mem_access::Width)width);
      }
    else
      {
        // When memory reads get enabled for a device we need to check if some
        // of the bar base addresses have changed and in this case need to do a
        // remap of them.
        if (cfg.reg() == Pci_hdr_command_offset && val & Memory_space_bit)
          remap_bars(&hw_device(cfg));
        // Pass-through to device
        device(cfg).cfg_write(cfg.reg(), val, 8 << width);
      }

    if (0)
      trace().printf("write cfg id=%u offs=0x%x width=%d val=0x%x raw=0x%x\n",
                     cfg.dev().get(), cfg.reg().get(), (int)width, val, reg);
  }

private:
  /**
   * PCI bar configuration.
   *
   * Internal representation of a bar configuration.
   */
  struct Pci_cfg_bar
  {
    enum Type
    {
      Unused, /// Not used
      MMIO32, /// 32bit MMIO
      MMIO64, /// 64bit MMIO
      IO      /// IO space
    };

    l4_uint64_t io_addr = 0;  /// Address used by IO
    l4_uint64_t map_addr = 0; /// Address to use for the guest mapping
    l4_uint64_t size = 0;     /// Size of the region
    Type type = Unused;       /// Type of the bar

    static const char *to_string(Type t)
    {
      switch(t)
        {
          case IO: return "io";
          case MMIO32: return "mmio32";
          case MMIO64: return "mmio64";
          default: return "unused";
        }
    }
  };

  /**
   * Internal PCI device.
   */
  struct Hw_pci_device
  {
    explicit Hw_pci_device(L4vbus::Pci_dev d, unsigned dev_id)
    : dev_id(dev_id),
      dev(d)
    {}

    /*
     * Disable access to the PCI device.
     *
     * The current configuration will be returned and has to be passed to the
     * enabled_access function to restore the correct configuration when
     * enabling the device again.
     *
     * \return The current MMIO/IO space configuration bits
     */
    l4_uint32_t disable_access()
    {
      // Disable any bar access
      l4_uint32_t cmd_reg = 0;
      L4Re::chksys(dev.cfg_read(Pci_hdr_command_offset, &cmd_reg, 16),
                   "Read Command register of PCI device header.");
      L4Re::chksys(dev.cfg_write(Pci_hdr_command_offset,
                                 cmd_reg & ~Access_mask, 16),
                   "Write Command register of PCI device header (disable "
                   "decode).");

      return cmd_reg & Access_mask;
    }

    /*
     * Enable access to the PCI device.
     *
     * \param access  The MMIO/IO space configuration bits to enable
     */
    void enable_access(l4_uint32_t access)
    {
      l4_uint32_t cmd_reg = 0;
      L4Re::chksys(dev.cfg_read(Pci_hdr_command_offset, &cmd_reg, 16),
                   "Read Command register of PCI device header.");
      // Reenable bar access
      L4Re::chksys(dev.cfg_write(Pci_hdr_command_offset,
                                 cmd_reg | (access & Access_mask), 16),
                   "Write Command register of PCI device header (enable "
                   "decode).");
    }

    /**
     * Parses one bar configuration for a specific device.
     *
     * \pre  Because this modifies the base address register the PCI device
     *       access must be disabled before calling this method.
     *
     * \post This may advance the bar offset in case of an 64 bit mmio bar. 64
     *       bit addresses take up two bars.
     */
    unsigned read_bar(unsigned bar_offs,
                      l4_uint64_t *addr, l4_uint64_t *size,
                      Pci_cfg_bar::Type *type) const
    {
      // Read the base address reg
      l4_uint32_t bar = 0;
      l4_uint32_t bar_size = 0;
      L4Re::chksys(dev.cfg_read(bar_offs, &bar, 32),
                   "Read BAR register of PCI device header.");
      if ((bar & Bar_type_mask) == Bar_io_space_bit) // IO bar
        {
          bar_offs = read_bar_size(bar_offs, bar, &bar_size);
          if (bar_size == 0)
            return bar_offs;

          bar_size &= ~Bar_io_attr_mask; // clear decoding

          *type = Pci_cfg_bar::IO;
          *addr = bar & ~Bar_io_attr_mask;
          *size = (~bar_size & 0xffff) + 1;
        }
      else if ((bar & Bar_mem_type_mask) == Bar_mem_type_32bit) // 32Bit MMIO bar
        {
          bar_offs = read_bar_size(bar_offs, bar, &bar_size);
          if (bar_size == 0)
            return bar_offs;

          bar_size &= ~Bar_mem_attr_mask; // clear decoding

          *type = Pci_cfg_bar::MMIO32;
          *addr = bar & ~Bar_mem_attr_mask;
          *size = ~bar_size + 1;
        }
      else if ((bar & Bar_mem_type_mask) == Bar_mem_type_64bit) // 64Bit MMIO bar
        {
          // Process the first 32bit
          l4_uint64_t addr64 = bar & ~Bar_mem_attr_mask;
          l4_uint64_t size64 = 0;
          bar_offs = read_bar_size(bar_offs, bar, &bar_size);
          if (bar_size == 0)
            return bar_offs;

          size64 = bar_size;

          // Process the second 32bit
          L4Re::chksys(dev.cfg_read(bar_offs, &bar, 32),
                       "Read BAR register of PCI device header.");
          addr64 |= (l4_uint64_t)bar << 32; // shift to upper part
          bar_offs = read_bar_size(bar_offs, bar, &bar_size);

          size64 |= (l4_uint64_t)bar_size << 32; // shift to upper part
          size64 &= ~Bar_mem_attr_mask; // clear decoding

          *type = Pci_cfg_bar::MMIO64;
          *addr = addr64;
          *size = ~size64 + 1;
        }

      return bar_offs;
    }

    /**
     * Queries the size of a bar.
     */
    unsigned read_bar_size(unsigned bar_offs, l4_uint32_t bar,
                           l4_uint32_t *bar_size) const
    {
      L4Re::chksys(dev.cfg_write(bar_offs, 0xffffffffUL, 32),
                   "Write BAR register of PCI device header (sizing).");
      L4Re::chksys(dev.cfg_read(bar_offs, bar_size, 32),
                   "Read BAR register of PCI device header (size).");
      L4Re::chksys(dev.cfg_write(bar_offs, bar, 32),
                   "Write BAR register of PCI device header (write back).");
      return bar_offs + 4;
    }

    unsigned dev_id;                     /// Virtual device id
    L4vbus::Pci_dev dev;                 /// Reference to vbus PCI device
    Pci_cfg_bar bars[Bar_num_max_type0]; /// Bar configurations
    cxx::Ref_ptr<Vdev::Irq_svr> irq;
  };

  /**
   * Return type 0 PCI header for the virtual PCIe host controller.
   */
  Pci_header::Type0 *header()
  { return get_header<Pci_header::Type0>(); }

  /**
   * Return the hw device referred to in the configuration address.
   */
  Hw_pci_device &hw_device(Cfg_addr const &cfg)
  { return _devices[cfg.dev() - 1]; }

  /**
   * Return the device referred to in the configuration address.
   */
  L4vbus::Pci_dev &device(Cfg_addr const &cfg)
  { return hw_device(cfg).dev; }

  /**
   * Iterate the root bus and setup any PCI devices found.
   */
  void iterate_pci_root_bus(cxx::Ref_ptr<Vmm::Virt_bus> const &vbus,
                            Interrupt_map const &irq_map)
  {
    auto root = vbus->bus()->root();
    L4vbus::Pci_dev pdev;
    l4vbus_device_t dinfo;
    info().printf("Scanning PCI devices...\n");
    while (root.next_device(&pdev, L4VBUS_MAX_DEPTH, &dinfo) == L4_EOK)
      {
        if (!l4vbus_subinterface_supported(dinfo.type, L4VBUS_INTERFACE_PCIDEV))
          continue;

        l4_uint32_t vendor_device = 0;
        if (pdev.cfg_read(Pci_hdr_vendor_id_offset, &vendor_device, 32) != L4_EOK)
          continue;

        if (vendor_device == Pci_invalid_vendor_id)
          continue;

        Hw_pci_device hw_dev(pdev, _devices.size() + 1);
        info().printf("Found PCI device: name='%s', vendor/device=%04x:%04x\n",
                      dinfo.name, vendor_device & 0xffff, vendor_device >> 16);

        setup_device_bars(vbus, &hw_dev);
        setup_device_irq(vbus, irq_map, &hw_dev, dinfo);

        _devices.emplace_back(std::move(hw_dev));
      }
  }

  /**
   * Parses and setup all bars for a specific device.
   */
  void setup_device_bars(cxx::Ref_ptr<Vmm::Virt_bus> const &vbus,
                         Hw_pci_device *hw_dev) const
  {
    // Disable any bar access
    l4_uint32_t access = hw_dev->disable_access();

    for (unsigned bar_offs = Pci_hdr_base_addr0_offset, i = 0;
         bar_offs <= Pci_hdr_base_addr5_offset; ++i)
      {
        Pci_cfg_bar &bar = hw_dev->bars[i];

        // Read one bar configuration
        bar_offs = hw_dev->read_bar(bar_offs, &bar.io_addr, &bar.size,
                                    &bar.type);

        if (bar.type == Pci_cfg_bar::Unused)
          continue;

        // Initial map address is equal to io address
        bar.map_addr = bar.io_addr;


        info().printf("  bar[%u] addr=0x%llx size=0x%llx type=%s\n", i,
                      bar.io_addr, bar.size, Pci_cfg_bar::to_string(bar.type));

        // Now create the mmio mapping
        if (bar.type == Pci_cfg_bar::MMIO32 ||
            bar.type == Pci_cfg_bar::MMIO64)
          {
            trace().printf("command map [%u] io_addr=0x%llx -> map_addr=0x%llx "
                           "size=0x%llx type=%s\n", i, bar.io_addr, bar.map_addr,
                           bar.size, Pci_cfg_bar::to_string(bar.type));
            // Mark region as moveable so it can't be merged
            auto region = Vmm::Region::ss(Vmm::Guest_addr(bar.map_addr),
                                          bar.size,
                                          Vmm::Region_type::Vbus,
                                          Vmm::Region_flags::Moveable);
            // Disable eager mapping, because this gets most likely remapped anyway
            cxx::Ref_ptr<Ds_handler> ds_handler =
              Vdev::make_device<Ds_handler>(vbus->io_ds(), 0x0, bar.size, bar.io_addr,
                                            Ds_handler::None);
            _vmm->add_mmio_device(region, ds_handler);
          }
      }

    // Reenable bar access
    hw_dev->enable_access(access);
  }

  /**
   * Remap all bars if necessary.
   *
   * Checks for all bars if the base address has changed and remap the mmio
   * handler to the new address if necessary.
   *
   * Note: This also unmaps any previous child mappings of the previous used
   * region in the vm_task.
   */
  void remap_bars(Hw_pci_device *hw_dev) const
  {
    // Disable any bar access
    l4_uint32_t access = hw_dev->disable_access();

    for (unsigned bar_offs = Pci_hdr_base_addr0_offset, i = 0;
         bar_offs <= Pci_hdr_base_addr5_offset; ++i)
      {
        Pci_cfg_bar &bar = hw_dev->bars[i];
        // We are only interested in mmio regions
        if (bar.type == Pci_cfg_bar::IO)
          {
            bar_offs += 4;
            continue;
          }

        l4_uint64_t addr = 0, size = 0;
        Pci_cfg_bar::Type type = Pci_cfg_bar::Unused;
        // Read the current device bar configuration
        bar_offs = hw_dev->read_bar(bar_offs, &addr, &size, &type);
        // If the address has changed we need to do a remap
        if (bar.map_addr != addr)
          {
            trace().printf("command remap [%u] io_addr=0x%llx -> "
                           "map_addr=0x%llx (from: map_addr=0x%llx) "
                           "size=0x%llx type=%s\n", i, bar.io_addr, addr,
                           bar.map_addr, bar.size,
                           Pci_cfg_bar::to_string(bar.type));
            auto old_region = Vmm::Region::ss(Vmm::Guest_addr(bar.map_addr),
                                              bar.size,
                                              Vmm::Region_type::Vbus,
                                              Vmm::Region_flags::Moveable);
            // Instruct the vm map to use the new start address
            _vmm->remap_mmio_device(old_region, Vmm::Guest_addr(addr));
            // Unmap any child mappings which may be happened in the meantime
            auto vm_task = _vmm->vm_task();
            l4_addr_t src = bar.map_addr;
            while (src < bar.map_addr + bar.size - 1)
              {
                vm_task->unmap(l4_fpage(src, L4_PAGESHIFT, 0), L4_FP_ALL_SPACES);
                src += L4_PAGESIZE;
              }
            // Update our internal mapping address
            bar.map_addr = addr;
          }
      }

    // Reenable bar access
    hw_dev->enable_access(access);
  }

  /**
   * Parses and setup the interrupt for a specific device.
   */
  void setup_device_irq(cxx::Ref_ptr<Vmm::Virt_bus> const &vbus,
                        Interrupt_map const &irq_map, Hw_pci_device *hw_dev,
                        l4vbus_device_t const &dinfo)
  {
    unsigned pin = 0;
    L4Re::chksys(hw_dev->dev.cfg_read(Pci_hdr_interrupt_pin_offset, &pin, 8),
                 "Read interrupt pin register of PCI device header.");
    if (pin == 0) // No legacy interrupt messages enabled
      return;

    // Apply interrupt pin mask
    pin &= irq_map.pin_mask;

    // Apply device id mask
    unsigned dev_id = (hw_dev->dev_id << 11) & irq_map.dev_id_mask;
    if (!irq_map.map.count(dev_id))
      L4Re::chksys(-L4_EINVAL, "PCI device not found in interrupt map.");

    // Query the corresponding irq/ic entry based on the device id and irq pin
    int map_irq = irq_map.map.at(dev_id).targets[pin - 1].irq;
    cxx::Ref_ptr<Gic::Ic> ic = irq_map.map.at(dev_id).targets[pin - 1].ic;

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
    hw_dev->irq = cxx::make_ref_obj<Vdev::Irq_svr>(_vmm->registry(), vbus->icu(),
                                            io_irq, ic, map_irq);
    hw_dev->irq->eoi();
    info().printf("  IRQ mapping: %d -> %d\n", io_irq, map_irq);
  }

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCIe ctl"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCIe ctl"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCIe ctl"); }

  Vmm::Guest *_vmm;
  std::vector<Hw_pci_device> _devices;
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
