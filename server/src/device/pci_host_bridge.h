/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>
#include "virt_bus.h"
#include "irq_svr.h"
#include "guest.h"

namespace Vdev { namespace Pci {

/*
 * Enumerate PCI devices on vbus.
 */
class Pci_host_bridge
{
public:
  Pci_host_bridge(Device_lookup *devs)
  : _vmm(devs->vmm()),
    _vbus(devs->vbus())
  {}

  /**
   * Internal PCI device.
   */
  struct Hw_pci_device : public Pci_device
  {
    explicit Hw_pci_device(L4vbus::Pci_dev d, unsigned dev_id,
                           l4vbus_device_t const &dinfo)
    : dev_id(dev_id),
      dev(d),
      dinfo(dinfo)
    {}

    l4_uint64_t src_id() const override
    { return dev.dev_handle() | (1ULL << 63); }

    /**
     * Convert Mem_access, which is given in bytes, into bits.
     *
     * The same as (8 << width), but we let the compiler do the optimization.
     */
    inline l4_uint32_t mem_access_to_bits(Vmm::Mem_access::Width width) const
    {
      switch (width)
        {
        case Vmm::Mem_access::Width::Wd8:
          return 8;
        case Vmm::Mem_access::Width::Wd16:
          return 16;
        case Vmm::Mem_access::Width::Wd32:
          return 32;
        case Vmm::Mem_access::Width::Wd64:
          return 64;
        default:
          L4Re::throw_error(-L4_EINVAL, "Cannot convert value to bits.\n");
        }
    }

    void cfg_write(unsigned reg, l4_uint32_t value, Vmm::Mem_access::Width width)
    {
      L4Re::chksys(dev.cfg_write(reg, value, mem_access_to_bits(width)),
                   "PCI config space access: write\n");
    }

    void cfg_read(unsigned reg, l4_uint32_t *value, Vmm::Mem_access::Width width)
    {
      L4Re::chksys(dev.cfg_read(reg, value, mem_access_to_bits(width)),
                   "PCI config space access: read\n");
    }

    unsigned dev_id;                     /// Virtual device id
    L4vbus::Pci_dev dev;                 /// Reference to vbus PCI device
    l4vbus_device_t dinfo;               /// vbus device info
    cxx::Ref_ptr<Vdev::Irq_svr> irq;
  };

  /**
   * Return the hw device referred to in the configuration address.
   */
  Pci_device *device(l4_uint32_t devid)
  { return _devices[devid].get(); }

  /**
   * Handle incoming config space read
   *
   * \returns read value
   */
  l4_uint32_t cfg_space_read(l4_uint32_t devid, unsigned reg, Vmm::Mem_access::Width width)
  {
    l4_uint32_t value = -1U;
    if (devid >= _devices.size())
      return value;

    if (device(devid))
      device(devid)->cfg_read(reg, &value, width);

    if (0)
      trace().printf("read cfg dev=%u width=%d raw=0x%x val=0x%x\n",
                     devid, (int)width, reg, value);
    return value;
  }

  /**
   * Handle incoming config space write
   */
  void cfg_space_write(l4_uint32_t devid, unsigned reg, Vmm::Mem_access::Width width, l4_uint32_t value)
  {
    if (devid >= _devices.size())
      return;

    if (devid == 0)
        // Virtual bridge
        // - no bar support
        // - no expansion ROM support
        if ((   reg >= Pci_hdr_base_addr0_offset
             && reg <= Pci_hdr_base_addr5_offset)
            ||  reg == Pci_hdr_expansion_rom_offset)
          return;

    // When memory reads get enabled for a device we need to check if some
    // of the bar base addresses have changed and in this case need to do a
    // remap of them.
    if (reg == Pci_hdr_command_offset && value & Memory_space_bit)
      remap_bars(device(devid));
    // Pass-through to device
    if (device(devid))
      device(devid)->cfg_write(reg, value, width);

    if (0)
      trace().printf("write cfg dev=%u width=%d reg=0x%x\n",
                     devid, (int)width, reg);
  }

protected:
  /**
   * Iterate the root bus and setup any PCI devices found.
   */
  void iterate_pci_root_bus()
  {
    if (!_vbus.get() || !_vbus->available())
      return;

    auto root = _vbus->bus()->root();
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

        Hw_pci_device *h = new Hw_pci_device(pdev, _devices.size(), dinfo);
        info().printf("Found PCI device: name='%s', vendor/device=%04x:%04x\n",
                      dinfo.name, vendor_device & 0xffff, vendor_device >> 16);

        h->parse_device_bars();
        h->parse_msix_cap();

        init_dev_resources(h);

        register_device(cxx::Ref_ptr<Pci_device>(h));
      }
  }

  virtual void init_dev_resources(Hw_pci_device *) = 0;

public:
  /**
   * Remap all bars if necessary.
   *
   * Checks for all bars if the base address has changed and remap the mmio
   * handler to the new address if necessary.
   *
   * Note: This also unmaps any previous child mappings of the previous used
   * region in the vm_task.
   */
  void remap_bars(Pci_device *hw_dev) const
  {
    remap_mmio_bars(hw_dev);
  }

  /**
   * Remap MMIO bars if necessary.
   */
  void remap_mmio_bars(Pci_device *hw_dev) const
  {
    assert(hw_dev != nullptr);
    // Disable any bar access
    l4_uint32_t access = hw_dev->disable_access();

    // BAR indicator register. Used to determine MSIX-emulation memory.
    unsigned bir = Pci_config_consts::Bar_num_max_type0;
    if (hw_dev->has_msix)
      bir = hw_dev->msix_cap.tbl.bir();

    for (unsigned bar_offs = Pci_hdr_base_addr0_offset, i = 0;
         bar_offs <= Pci_hdr_base_addr5_offset; ++i)
      {
        if (bar_offs == bir) // we currently cannot move the bir
          continue;

        Pci_cfg_bar &bar = hw_dev->bars[i];
        // We are only interested in mmio regions
        if (bar.type == Pci_cfg_bar::IO || bar.type == Pci_cfg_bar::Unused)
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
            assert(bar.size);

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
   * Register a UVMM emulated device.
   *
   * In case the PCI bus is full, an exception is thrown.
   */
  void register_device(cxx::Ref_ptr<Pci_device> const &dev)
  {
    printf("Registering device %zu\n", _devices.size() + 1);
    _devices.push_back(dev);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI vbus"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI vbus"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI vbus"); }

protected:
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  // used for device lookup on PCI config space access
  // may contain physical and virtual devices
  std::vector<cxx::Ref_ptr<Pci_device>> _devices;
};

}}
