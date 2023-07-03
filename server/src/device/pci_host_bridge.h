/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */

#pragma once

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>

#include "virt_bus.h"
#include "irq_svr.h"
#include "guest.h"
#include "pci_device.h"
#include "msi.h"
#include "msi_controller.h"
#include "msi_memory.h"
#include "address_space_manager_mode_if.h"
#include "ds_mmio_handling.h"

namespace Vdev { namespace Pci {

/**
 * Parse the bus-range property of the device tree node of the PCI host bridge.
 *
 * \param node        Device tree node.
 * \param start[out]  Returns the start of the handled bus range.
 * \param end[out]    Returns the inclusive end of the handled bus range.
 *
 * \retval true   bus-range property found and `start` and `end` valid.
 * \retval false  bus-range property not found or faulty. `start` and `end`
 *                invalid.
 */
bool
parse_bus_range(Dt_node const &node, unsigned char *start, unsigned char *end);

/**
 * PCI bus managing devices 'plugged' into it.
 */
class Pci_bus
{
  enum
  {
    Max_num_devs = 32,
    Invalid_dev_id = 0xffffffff,
  };

public:
  // Create a PCI bus with the specified bus number.
  explicit Pci_bus(unsigned char num) : _bus_num(num) {}

  /**
   * Return the hw device referred to in the configuration address.
   */
  Pci_device *device(l4_uint32_t devid)
  { return _devices[devid].get(); }

  /// Number of registered devices on this bus.
  size_t num_devices() const
  { return _devices.size(); }

  /// Number of this bus.
  unsigned char bus_num() const
  { return _bus_num; };

  /**
   * Register a UVMM emulated device.
   *
   * Disables the device to meet the required reset state. We also have not yet
   * registered any MMIO/IO resources for the guest.
   *
   * \param dev     Device to register.
   * \param dev_id  Device ID to register the device with, must be allocated via
   *                `alloc_dev_id()`, with the exception of `Invalid_dev_id`,
   *                which instead instructs this method to allocate a device ID.
   *
   * \throws L4::Bounds_error   If an out-of-range device ID is provided.
   * \throws L4::Out_of_memory  If `Invalid_dev_id` was passed for `dev_id`, but
   *                            allocating a device ID failed because there was
   *                            no more free device ID.
   */
  void register_device(cxx::Ref_ptr<Pci_device> const &dev,
                       unsigned dev_id = Invalid_dev_id)
  {
    if (dev_id == Invalid_dev_id)
      dev_id = alloc_dev_id();
    else if (dev_id >= Max_num_devs)
      L4Re::throw_error(-L4_ERANGE,
                        "Provided device ID is in the range [0, 31].");

    info().printf("Registering PCI device %.02x:%.02x.0\n", _bus_num, dev_id);

    if (dev_id >= _devices.size())
      _devices.resize(dev_id + 1);

    dev->disable_access(Access_mask); // PCI devices are disabled by default.
    _devices[dev_id] = dev;
  }

  /**
   * Allocate a device ID, which can be used to register a PCI device on this
   * bus.
   *
   * \return Allocated device ID.
   *
   * \throws L4::Out_of_memory  If the allocation failed because there is no
   *                            more free device ID.
   */
  unsigned alloc_dev_id()
  {
    long dev_id = _dev_id_alloc.scan_zero();
    if (dev_id < 0)
      L4Re::throw_error(-L4_ENOMEM,
                        "PCI bus can accommodate no more than 32 devices. "
                        "Consider putting the device on another PCI bus.");
    _dev_id_alloc.set_bit(dev_id);
    return dev_id;
  }

private:
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI bus"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI bus"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI bus"); }

  unsigned char _bus_num;
  // used for device lookup on PCI config space access
  // may contain physical and virtual devices
  std::vector<cxx::Ref_ptr<Pci_device>> _devices;
  cxx::Bitmap<Max_num_devs> _dev_id_alloc;
};

/*
 * PCI host bridge managing device accesses from the guest OS.
 *
 * It also iterates all PCI the vBus and places them on the virtual PCI bus to
 * make them visible to the guest.
 */
class Pci_host_bridge : public Virt_pci_device
{
public:
  /**
   * Create a PCI host bridge for the given PCI bus number.
   */
  Pci_host_bridge(Device_lookup *devs, unsigned char bus_num,
                  cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl)
  : _vmm(devs->vmm()),
    _vbus(devs->vbus()),
    _as_mgr(devs->ram()->as_mgr_if()),
    _bus(bus_num),
    _msix_ctrl(msix_ctrl)
  {
    if (msix_ctrl)
      _msi_src_factory = make_device<
        Vdev::Msi::Msi_src_factory>(cxx::static_pointer_cast<Msi::Allocator>(
                                      devs->vbus()),
                                    devs->vmm()->registry());
  }

  /// provide access to the bus
  Pci_bus *bus() { return &_bus; }

  /**
   * A hardware PCI device present on the vBus.
   */
  struct Hw_pci_device : public Pci_device
  {
    explicit Hw_pci_device(Pci_host_bridge *parent, L4vbus::Pci_dev d,
                           unsigned dev_id, l4vbus_device_t const &dinfo)
    : parent(parent),
      dev_id(dev_id),
      dev(d),
      dinfo(dinfo)
    {}

    l4_uint64_t src_id() const override
    { return dev.dev_handle() | L4vbus::Icu::Src_dev_handle; }

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
     * For some devices IO adds additional resources to the vbus device.
     *
     * Uvmm handles PCI resources via the PCI BAR registers.
     * In this function we discover all mem resources from the vbus and map
     * those that are not yet handled through PCI BARs.
     */
    void map_additional_iomem_resources(Vmm::Guest *vmm,
                                        L4::Cap<L4Re::Dataspace> io_ds)
    {
      for (unsigned i = 0; i < dinfo.num_resources; ++i)
        {
          l4vbus_resource_t res;
          L4Re::chksys(dev.get_resource(i, &res),
                       "Cannot get vbus resource.");

          // we only handle iomem resources
          if (res.type != L4VBUS_RESOURCE_MEM)
            continue;

          unsigned mmio_space_rw = L4VBUS_RESOURCE_F_MEM_MMIO_READ
                                 | L4VBUS_RESOURCE_F_MEM_MMIO_WRITE;
          bool is_mmio_space = res.flags & mmio_space_rw;

          // we only handle mmio resources (not spaces)
          if (is_mmio_space)
            continue;

          auto size = res.end - res.start + 1;
          // we only handle resources that are not handled via PCI BARs
          bool is_pci_bar = false;
          for (unsigned j = 0; j < Bar_num_max_type0; ++j)
            {
              if (bars[j].type == Pci_cfg_bar::Unused_empty
                  || bars[j].type == Pci_cfg_bar::Reserved_mmio64_upper
                  || bars[j].type == Pci_cfg_bar::IO)
                continue;
              if (res.start == bars[j].io_addr
                  && size == bars[j].size)
                is_pci_bar = true;
            }
          if (is_pci_bar)
            continue;

          info().printf("Additional MMIO resource %s.%.4s : "
                        "[0x%lx - 0x%lx] flags = 0x%x\n",
                        dinfo.name, reinterpret_cast<char const *>(&res.id),
                        res.start, res.end, res.flags);
          auto region = Vmm::Region::ss(Vmm::Guest_addr(res.start),
                                        size,
                                        Vmm::Region_type::Vbus);
          l4_uint32_t rights = 0;
          if (res.flags & L4VBUS_RESOURCE_F_MEM_R)
            rights |= L4_FPAGE_RO;
          if (res.flags & L4VBUS_RESOURCE_F_MEM_W)
            rights |= L4_FPAGE_W;
          auto handler =
            Vdev::make_device<Ds_handler>(
                cxx::make_ref_obj<Vmm::Ds_manager>(io_ds, res.start, size,
                                                   L4Re::Rm::Region_flags(rights)),
                static_cast<L4_fpage_rights>(rights)
              );
          vmm->add_mmio_device(region, handler);
        }
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

    /// Setup virtual MSI-X table and map vbus resources as needed.
    void setup_msix_table();

    Pci_host_bridge *parent;             /// Parent host bridge of device
    unsigned dev_id;                     /// Virtual device id
    L4vbus::Pci_dev dev;                 /// Reference to vbus PCI device
    l4vbus_device_t dinfo;               /// vbus device info
    cxx::Ref_ptr<Vdev::Irq_svr> irq;
    cxx::Ref_ptr<Ds_access_mgr> msix_table_page_mgr;
    cxx::Ref_ptr<Msix::Virt_msix_table> msix_table;
    cxx::Ref_ptr<Vdev::Msi::Msi_src> msi_src;

  protected:
    void add_decoder_resources(Vmm::Guest *, l4_uint32_t access) override;
    void del_decoder_resources(Vmm::Guest *, l4_uint32_t access) override;

    void add_exp_rom_resource() override;
    void del_exp_rom_resource() override;

  private:
    void add_io_bar_resources(Pci_cfg_bar const &bar);
    void add_mmio_bar_resources(Pci_cfg_bar const &bar);
    void add_msix_bar_resources(Pci_cfg_bar const &bar);
    void del_io_bar_resources(Pci_cfg_bar const &bar);
    void del_mmio_bar_resources(Pci_cfg_bar const &bar);
    void del_msix_bar_resources(Pci_cfg_bar const &bar);

    void msi_cap_write_ctrl(l4_uint16_t ctrl);

    static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "HW PCI dev"); }
    static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "HW PCI dev"); }
    static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "HW PCI dev"); }

    std::mutex _mutex;                   /// Protect MSI cap reads/writes
  };

  /**
   * Handle incoming config space read
   *
   * \returns read value
   */
  l4_uint32_t cfg_space_read(l4_uint32_t devid, unsigned reg, Vmm::Mem_access::Width width)
  {
    l4_uint32_t value = -1U;
    if (devid >= _bus.num_devices())
      return value;

    if (auto dev = _bus.device(devid))
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
    if (devid >= _bus.num_devices())
      return;

    // Pass-through to device
    if (auto dev = _bus.device(devid))
      dev->cfg_write(_vmm, reg, value, width);

    if (0)
      info().printf("write cfg dev=%u width=%d reg=0x%x, value=0x%x\n",
                     devid, (int)width, reg, value);
  }

protected:
  /**
   * Setup and register devices, i.e. the host bridge itself and any PCI devices
   * discovered on the root bus.
   *
   * This must be a separate method called from the constructor of classes
   * derived from Pci_host_bridge, since iterate_pci_root_bus() calls virtual
   * methods.
   */
  void setup_devices()
  {
    unsigned dev_id = _bus.alloc_dev_id();
    iterate_pci_root_bus();

    // Registering the host bridge itself must be the last operation, otherwise
    // an exception thrown in the rest of the constructor would result in double
    // destruction of the host bridge (exception unwind destroys the
    // half-constructed host bridge, host bridge itself is removed from
    // _devices, drops its _refcount to zero, which destroys the host bridge in
    // destruction again).
    _bus.register_device(cxx::Ref_ptr<Pci_device>(this), dev_id);
  }

  /**
   * Iterate the root bus and setup any PCI devices found.
   */
  void iterate_pci_root_bus()
  {
    if (!_vbus.get() || !_vbus->available())
      return;

    // Without DMA we don't pass-through PCI devices.
    if (_as_mgr->is_no_dma_mode())
      {
        warn().printf("DMA disabled, will not add any physical PCI devices to "
                      "the PCI bridge!\n");
        return;
      }

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

        Hw_pci_device *h =
          new Hw_pci_device(this, pdev, _bus.alloc_dev_id(), dinfo);
        info().printf("Found PCI device: name='%s', vendor/device=%04x:%04x\n",
                      dinfo.name, vendor_device & 0xffff, vendor_device >> 16);

        h->parse_device_bars();
        h->parse_device_exp_rom();
        h->parse_msix_cap();
        h->parse_msi_cap();
        h->setup_msix_table();
        h->map_additional_iomem_resources(_vmm, _vbus->io_ds());
        init_dev_resources(h);

        if (!h->has_msi && !h->has_msix)
          warn().printf("\n\nDevice '%s' with vendor/device=%04x:%04x supports "
                        "neither MSI nor MSI-X. Legacy interrupts are not "
                        "supported. Device will not work properly.\n\n",
                        dinfo.name, vendor_device & 0xffff,
                        vendor_device >> 16);

        _bus.register_device(cxx::Ref_ptr<Pci_device>(h), h->dev_id);
      }
  }

  virtual void init_dev_resources(Hw_pci_device *) = 0;

public:
  /**
   * Return the virtual source ID for a PCI device registered on this host
   * bridge.
   *
   * This default implementation returns the plain Requester ID (bus, device and
   * function number). Derived implementations overriding this method might
   * want to apply a mapping to the Requester ID.
   */
  virtual l4_uint32_t msi_vsrc_id(unsigned dev_id) const
  {
    // The Requester ID consists of the bus number, device number and function
    // number. We do not support device function, therefore the following shift
    // accounts for the 3 bits allocated for the function number.
    return ((l4_uint32_t)_bus.bus_num()) << 8 | dev_id << 3;
  }

  /**
   * Return the MSI-X destination for a PCI device registered on this host
   * bridge.
   */
  Gic::Msix_dest msix_dest(unsigned dev_id) const
  {
    return Gic::Msix_dest(_msix_ctrl, msi_vsrc_id(dev_id));
  }

private:
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PCI hbr"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PCI hbr"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "PCI hbr"); }

protected:
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  Vmm::Address_space_manager_mode_if const *_as_mgr;
  Pci_bus _bus;
  /// MSI-X controller responsible for the devices of this PCIe host bridge,
  /// may be nullptr since MSI-X support is an optional feature.
  cxx::Ref_ptr<Gic::Msix_controller> _msix_ctrl;

  cxx::Ref_ptr<Vdev::Msi::Msi_src_factory> _msi_src_factory;
};

} } // namespace Vdev::Pci
