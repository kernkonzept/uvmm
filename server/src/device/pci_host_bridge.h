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
#include "pci_device.h"
#include "msi.h"
#include "msi_controller.h"
#include "address_space_manager_mode_if.h"

namespace Vdev { namespace Pci {

/*
 * Enumerate PCI devices on vbus.
 */
class Pci_host_bridge
{
public:
  Pci_host_bridge(Device_lookup *devs)
  : _vmm(devs->vmm()),
    _vbus(devs->vbus()),
    _as_mgr(devs->ram()->as_mgr_if())
  {}

  /**
   * A hardware PCI device present on the vBus.
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

    void cfg_write_raw(unsigned reg, l4_uint32_t value,
                       Vmm::Mem_access::Width width) override
    {
      if (has_msi && msi_cap_write(reg, value, width))
        return;

      L4Re::chksys(dev.cfg_write(reg, value, mem_access_to_bits(width)),
                   "PCI config space access: write\n");
    }

    void cfg_read_raw(unsigned reg, l4_uint32_t *value,
                      Vmm::Mem_access::Width width) override
    {
      if (has_msi && msi_cap_read(reg, value, width))
        return;

      L4Re::chksys(dev.cfg_read(reg, value, mem_access_to_bits(width)),
                   "PCI config space access: read\n");
    }

    /**
     * Check if the read access in in the range of the MSI cap and needs to be
     * emulated.
     *
     * \return true, iff read was to the MSI cap and is served.
     */
    bool msi_cap_read(unsigned reg, l4_uint32_t *value,
                       Vmm::Mem_access::Width width);

    /**
     * Check if the write access is in the range of the MSI cap and needs to be
     * emulated.
     *
     * \return true, iff write was to the MSI cap and is handled.
     *
     * If the MSI capability supports per-vector masking, writes to the mask
     * bits of the capability needs to be written to the HW device as well.
     */
    bool msi_cap_write(unsigned reg, l4_uint32_t value,
                       Vmm::Mem_access::Width width);

    /// write MSI cap of hardware device
    void cfg_space_write_msi_cap(l4_icu_msi_info_t *msiinfo = nullptr);

    unsigned dev_id;                     /// Virtual device id
    L4vbus::Pci_dev dev;                 /// Reference to vbus PCI device
    l4vbus_device_t dinfo;               /// vbus device info
    cxx::Ref_ptr<Vdev::Irq_svr> irq;
    Vdev::Msi::Msi_src_factory *msi_src_factory;
    cxx::Ref_ptr<Vdev::Msi::Msi_src> msi_src;

  private:
    static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "HW PCI dev"); }
    static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "HW PCI dev"); }
    static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "HW PCI dev"); }

    std::mutex _mutex;                   /// Protect MSI cap reads/writes
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

    if (auto dev = device(devid))
      dev->cfg_read(reg, &value, width);

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

    // Pass-through to device
    if (auto dev = device(devid))
      dev->cfg_write(_vmm, reg, value, width);

    if (0)
      info().printf("write cfg dev=%u width=%d reg=0x%x, value=0x%x\n",
                     devid, (int)width, reg, value);
  }

protected:
  /**
   * Iterate the root bus and setup any PCI devices found.
   */
  void iterate_pci_root_bus()
  {
    if (!_vbus.get() || !_vbus->available())
      return;

    // Without DMA we don't pass-through PCI devices.
    if (_as_mgr->is_no_dma_mode())
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
        h->parse_msi_cap();

        init_dev_resources(h);

        register_device(cxx::Ref_ptr<Pci_device>(h));
      }
  }

  /**
   * Set up management of the MSI-X table page.
   *
   * \param  hwdev      Device for which MSI-X table is to be set up.
   * \param  bar        Index of the BAR containing the MSI-X table.
   * \param  msix_ctrl  MSI-X controller responsible for the device.
   */
  void register_msix_table_page(
    Pci_host_bridge::Hw_pci_device *hwdev, unsigned bir,
    cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl);

  /**
   * Register non-MSI-X table pages as pass-through MMIO regions.
   *
   * \param bar         BAR containing the MSI-X table.
   * \param tbl_offset  Offset of the MSI-X table inside `bar`.
   */
  void register_msix_bar(Pci_cfg_bar const *bar, l4_addr_t tbl_offset);

  /**
   * If the device supports MSI-X, set up the BAR used for the MSI-X table.
   *
   * If the device supports MSI-X, but no MSI-X controller is supplied, the
   * MSI-X table will not be mapped. However, the remainder of the BAR will be
   * mapped anyway.
   *
   * \param  hwdev      Device for which MSI-X is to be set up.
   * \param  msix_ctrl  MSI-X controller responsible for the device.
   *
   * \return The index of the BAR used for the MSI-X table if the device
   *         supports MSI-X, otherwise Pci_config_consts::Bar_num_max_type0.
   */
  unsigned setup_msix_memory(
    Hw_pci_device *hwdev, cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl);

  virtual void init_dev_resources(Hw_pci_device *) = 0;

public:
  /**
   * Register a UVMM emulated device.
   *
   * In case the PCI bus is full, an exception is thrown.
   */
  void register_device(cxx::Ref_ptr<Pci_device> const &dev)
  {
    if (_devices.size() > 31)
      L4Re::throw_error(-L4_ENOMEM,
                        "PCI bus can accomodate no more than 32 devices. "
                        "Consider putting the device on another PCI bus.");
    warn().printf("Registering device %zu\n", _devices.size() + 1);
    _devices.push_back(dev);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI vbus"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI vbus"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI vbus"); }

protected:
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  Vmm::Address_space_manager_mode_if const *_as_mgr;
  // used for device lookup on PCI config space access
  // may contain physical and virtual devices
  std::vector<cxx::Ref_ptr<Pci_device>> _devices;
};

} } // namespace Vdev::Pci
