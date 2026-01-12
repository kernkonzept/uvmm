/*
 * Copyright (C) 2021-2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>
#include <atomic>

#include "virt_bus.h"
#include "irq_svr.h"
#include "guest.h"
#include "pci_device.h"
#include "virt_pci_device.h"
#include "msi.h"
#include "msi_controller.h"
#include "msi_memory.h"
#include "ds_mmio_handling.h"
#include "pci_bridge_windows.h"

namespace Vdev { namespace Pci {

/**
 * PCI legacy interrupt to guest IRQ forwarder.
 *
 * Forwards L4Re interrupts to an Vmm::Irq_sink. We cannot just forward vbus
 * interrupts directly to guest interrupts via Vdev::Irq_svr because:
 *
 *   - There might be multiple devices sharing the same IRQ on the vbus vicu.
 *     We can only bind once to the vicu interrupt.
 *   - There might be multiple devices that are mapped to the same guest IRQ
 *     by the interrupt-map. These devices do not necessarily share the same
 *     IRQ on the vicu!
 *
 * Effectively this amounts to an n:m mapping. When acknowledging interrupts we
 * can rely on the fact that all are level triggered. If interrupt sources are
 * acknowledged incorrectly, they will re-trigger immediately.
 */
class Legacy_irq_router
{
  class Guest_pci_irq;

  class Host_pci_irq : public L4::Irqep_t<Host_pci_irq>
  {
    std::vector<Guest_pci_irq *> _sinks;
    L4::Cap<L4::Irq_eoi> _eoi;
    unsigned _irq;
    l4_uint32_t _source_mask;
    std::atomic<bool> _triggered = false;

  public:
    Host_pci_irq(L4Re::Util::Object_registry *registry, L4::Cap<L4::Icu> icu,
                 unsigned host_irq, unsigned index)
    : _irq(host_irq), _source_mask(1U << (index & 31U))
    {
      L4Re::chkcap(registry->register_irq_obj(this), "Cannot register IRQ");

      int ret = L4Re::chksys(icu->bind(host_irq, obj_cap()),
                             "Cannot bind to IRQ");
      switch (ret)
        {
        case 0:
          Dbg(Dbg::Dev, Dbg::Info, "irq_svr")
            .printf("IRQ %u will be unmasked directly\n", host_irq);
          _eoi = obj_cap();
          break;
        case 1:
          Dbg(Dbg::Dev, Dbg::Info, "irq_svr")
            .printf("IRQ %u will be unmasked at ICU\n", host_irq);
          _eoi = icu;
          break;
        default:
          L4Re::throw_error(-L4_EINVAL, "Invalid return code from bind to IRQ");
          break;
        }

      _eoi->unmask(_irq);
    }

    void handle_irq()
    {
      _triggered.store(true, std::memory_order_relaxed);
      for (auto *s : _sinks)
        s->inject(_source_mask);
    }

    void eoi(unsigned source_mask)
    {
      if ((_source_mask & source_mask) == 0)
        return;

      bool has_triggered = true;
      if (_triggered.compare_exchange_strong(has_triggered, false,
                                             std::memory_order_relaxed))
        _eoi->unmask(_irq);
    }

    void add_sink(Guest_pci_irq *dst)
    {
      for (auto *i : _sinks)
        if (i == dst)
          return;

      _sinks.push_back(dst);
    }
  };

  class Guest_pci_irq : public Gic::Irq_src_handler
  {
    std::vector<Host_pci_irq *> _sources;
    Vmm::Irq_sink _irq;
    std::atomic<l4_uint32_t> _triggers = 0;

  public:
    /**
     * Construct guest PCI IRQ.
     *
     * \param ic         Interrupt controller.
     * \param guest_irq  Guest IRQ.
     */
    Guest_pci_irq(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned guest_irq)
    {
      if (ic->get_irq_src_handler(guest_irq))
        L4Re::throw_error(-L4_EEXIST, "Bind IRQ for Guest_pci_irq object.");

      _irq.rebind(ic, guest_irq);
      _irq.set_irq_src_handler(this);
    }

    void inject(l4_uint32_t source_trigger)
    {
      l4_uint32_t prev_triggers =
        _triggers.fetch_or(source_trigger, std::memory_order_relaxed);

      // Inject (again) if a new source has triggered.
      if ((prev_triggers & source_trigger) != source_trigger)
        _irq.inject();
    }

    void eoi() override
    {
      _irq.ack();

      l4_uint32_t triggers = _triggers.load(std::memory_order_relaxed);
      while (!_triggers.compare_exchange_weak(triggers, 0,
                                              std::memory_order_relaxed))
        ;

      // EOI all sources with the collected triggers. Only the affected sources
      // will actually issue an EOI to the hardware interrupt.
      for (auto *s : _sources)
        s->eoi(triggers);
    }

    void add_source(Host_pci_irq *src)
    {
      for (auto *i : _sources)
        if (i == src)
          return;

      _sources.push_back(src);
    }
  };

public:
  Legacy_irq_router(L4Re::Util::Object_registry *registry,
                      L4::Cap<L4::Icu> icu)
  : _registry(registry), _icu(icu)
  {}

  /**
   * Add PCI legacy interrupt to guest IRQ forwarding route.
   *
   * \param host_irq   Host IRQ.
   * \param ic         Interrupt controller.
   * \param dev_id     PCI device ID.
   * \param pin        PCI interrupt pin (1 = A, 2 = B, 3 = C, 4 = D).
   * \param guest_irq  Guest IRQ.
   */
  void add_route(unsigned host_irq, cxx::Ref_ptr<Gic::Ic> const &ic,
                 unsigned dev_id, unsigned pin, unsigned guest_irq)
  {
    Host_pci_irq *source = get_source(host_irq);
    Guest_pci_irq *sink = get_sink(ic, guest_irq);
    unsigned guest_irq_prev = get_route(ic, dev_id, pin, guest_irq);

    if (guest_irq_prev != guest_irq)
      L4Re::throw_error(-L4_EINVAL,
                        "Contradictory PCI legacy interrupt routing.");

    source->add_sink(sink);
    sink->add_source(source);
  }

  /**
   * Generate the _PRT interrupt routing table for ACPI DSDT.
   *
   * Generate a _PRT interrupt routing table based on the PCI legacy interrupt
   * routes. Each PCI device, interrupt pin and guest IRQ tuple generates an
   * entry in the table. The guest IRQs are considered Global System
   * Interrupts.
   *
   * See ACPI Specification, Revision 6.5, Section 6.2.13 (PCI Routing Table).
   *
   * The AML templates are based on the following ASL:
   *
   * DefinitionBlock ("_prt.aml", "DSDT", 1, "UVMM  ", "KERNKONZ", 4) {
   *   Scope (\_SB.PCI0) {
   *     Name(_PRT, Package{
   *       Package{0x0FFFFFFF, 3, 0, 0x0FFAFAFA}
   *     })
   *   }
   * }
   *
   * Conversion (save above as _prt.asl):
   *   $ iasl _prt.aml
   *   $ xxd -i -s 0x24 -c 8 _prt.aml
   *
   * However, the AML templates which are actually used here have been manually
   * altered to use a 4-byte PkgLength encoding for the Total size (offset
   * 0x01) and Package size (offset 0x14) fields, as well as a WordConst
   * encoding for the Count (offset 0x19) field.
   *
   * \param[out] buf       Output buffer.
   * \param      max_size  Size of the buffer in bytes.
   *
   * \return Number of bytes generated.
   */
  l4_size_t amend_dsdt_with_prt(void *buf, l4_size_t max_size) const;

private:
  Host_pci_irq *get_source(unsigned host_irq)
  {
    auto it = _sources.find(host_irq);
    if (it != _sources.end())
      return it->second.get();

    auto *ret = new Host_pci_irq(_registry, _icu, host_irq, _sources.size());
    _sources[host_irq].reset(ret);
    return ret;
  }

  Guest_pci_irq *get_sink(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned guest_irq)
  {
    auto idx = std::make_tuple(ic.get(), guest_irq);
    auto it = _sinks.find(idx);
    if (it != _sinks.end())
      return it->second.get();

    auto *ret = new Guest_pci_irq(ic, guest_irq);
    _sinks[idx].reset(ret);
    return ret;
  }

  unsigned get_route(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned dev_id,
                     unsigned pin, unsigned guest_irq)
  {
    auto idx = std::make_tuple(ic.get(), dev_id, pin);
    auto it = _routes.find(idx);
    if (it != _routes.end())
      return it->second;

    _routes[idx] = guest_irq;
    return guest_irq;
  }

  /**
   * Encode a 4-byte ACPI PkgLength field.
   *
   * See ACPI Specification, Revision 6.5, Section 20.2.4 (Package Length
   * Encoding).
   *
   * \note The output buffer is assumed to contain space for at least 4 bytes.
   *
   * \param[out] buf    Output buffer.
   * \param      value  Value to encode.
   */
  static void encode_pkg_length_4b(unsigned char *buf, unsigned value)
  {
    assert(value <= 0x0fffffff);

    // Bits 6 & 7 set in the leading byte indicate the 4-byte encoding.
    // The leading byte also uses bits 0 to 3 for the least significant bits
    // of the value.
    buf[0] = 0xc0U | (value & 0x0fU);
    buf[1] = (value >> 4) & 0xffU;
    buf[2] = (value >> 12) & 0xffU;
    buf[3] = (value >> 20) & 0xffU;
  }

  L4Re::Util::Object_registry *_registry;
  L4::Cap<L4::Icu> _icu;
  std::map<unsigned, cxx::unique_ptr<Host_pci_irq>> _sources;
  std::map<std::tuple<Gic::Ic *, unsigned>,
           cxx::unique_ptr<Guest_pci_irq>> _sinks;
  std::map<std::tuple<Gic::Ic *, unsigned, unsigned>,
           unsigned> _routes;
};

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
  explicit Pci_bus(unsigned char num) : _bus_num(num)
  {
    _dev_id_alloc.clear_all();
  }

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
  static Dbg warn() { return Dbg(Dbg::Pci, Dbg::Warn, "PCI bus"); }
  static Dbg info() { return Dbg(Dbg::Pci, Dbg::Info, "PCI bus"); }
  static Dbg trace() { return Dbg(Dbg::Pci, Dbg::Trace, "PCI bus"); }

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
  Pci_host_bridge(Device_lookup *devs, Dt_node const &node,
                  unsigned char bus_num,
                  cxx::Ref_ptr<Gic::Msix_controller> msix_ctrl)
  : _vmm(devs->vmm()),
    _vbus(devs->vbus()),
    _irq_router(_vmm->registry(), _vbus->icu()),
    _bus(bus_num),
    _msix_ctrl(msix_ctrl),
    _windows(node)
  {
    if (msix_ctrl)
      _msi_src_factory = make_device<
        Vdev::Msi::Msi_src_factory>(cxx::static_pointer_cast<Msi::Allocator>(
                                      devs->vbus()),
                                    devs->vmm()->registry());
  }

  /// provide access to the bus
  Pci_bus *bus() { return &_bus; }

  /// access to bridge window management
  Pci_bridge_windows *bridge_windows() { return &_windows; }
  /// access to bridge window management
  Pci_bridge_windows const *bridge_windows() const { return &_windows; }

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

      if (has_sriov && sriov_cap_read(reg, value, width))
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
                                        L4::Cap<L4Re::Dataspace> io_ds);

    /**
     * Check if the read access is in the range of the MSI cap and needs to be
     * emulated.
     *
     * \return true, iff read was to the MSI cap and is emulated.
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

    /**
     * Check if the read access is in the range of the SR-IOV cap and needs to
     * be emulated.
     *
     * \return true, iff read was to the SR-IOV cap and is emulated.
     */
    bool sriov_cap_read(unsigned reg, l4_uint32_t *value,
                        Vmm::Mem_access::Width width);

    /**
     * Allocate BAR memory from the bridge windows.
     *
     * \pre BAR size already read from hardware device.
     */
    void alloc_bars_in_windows()
    {
      for (int i = 0; i < Bar_num_max_type0; ++i)
        {
          Pci_cfg_bar &bar = bars[i];

          if (bar.type >= Pci_cfg_bar::MMIO32 && bar.type <= Pci_cfg_bar::IO)
            bar.map_addr =
              parent->bridge_windows()->alloc_bar_resource(bar.size, bar.type);
          else
            continue;

          info().printf("  bar[%u] hw_addr=0x%llx map_addr=0x%llx size=0x%llx "
                        "type=%s\n",
                        i, bar.io_addr, bar.map_addr, bar.size,
                        bar.to_string());
        }

      // check if IO supports the expansion ROM, if so set it up.
      if (exp_rom.io_addr > 0 && exp_rom.size > 0)
        {
          exp_rom.map_addr =
            parent->bridge_windows()
              ->alloc_bar_resource(exp_rom.size, Pci_cfg_bar::Type::MMIO32);

          info().printf("  exp_rom hw_addr=0x%llx map_addr=0x%llx size=0x%llx "
                        "type=%s\n",
                        exp_rom.io_addr, exp_rom.map_addr, exp_rom.size,
                        "MMIO32");
        }
    }

    Pci_host_bridge *parent;             /// Parent host bridge of device
    unsigned dev_id;                     /// Virtual device id
    L4vbus::Pci_dev dev;                 /// Reference to vbus PCI device
    l4vbus_device_t dinfo;               /// vbus device info
    // HW IRQ resource managed in Legacy_irq_router;
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
  }; // struct Hw_pci_device

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
        h->alloc_bars_in_windows();
        h->parse_device_exp_rom();
        h->parse_msix_cap();
        h->parse_msi_cap();
        h->setup_msix_table();
        h->parse_sriov_cap();
        h->map_additional_iomem_resources(_vmm, _vbus->io_ds());
        init_dev_resources(h);

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

  /**
   * Generate the _PRT interrupt routing table for ACPI DSDT.
   *
   * \param[out] buf       Output buffer.
   * \param      max_size  Size of the buffer in bytes.
   *
   * \return Number of bytes generated.
   */
  l4_size_t amend_dsdt_with_prt(void *buf, l4_size_t max_size) const
  {
    return _irq_router.amend_dsdt_with_prt(buf, max_size);
  }

private:
  static Dbg trace() { return Dbg(Dbg::Pci, Dbg::Trace, "PCI hbr"); }
  static Dbg warn() { return Dbg(Dbg::Pci, Dbg::Warn, "PCI hbr"); }
  static Dbg info() { return Dbg(Dbg::Pci, Dbg::Info, "PCI hbr"); }

protected:
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  Legacy_irq_router _irq_router;
  Pci_bus _bus;
  /// MSI-X controller responsible for the devices of this PCIe host bridge,
  /// may be nullptr since MSI-X support is an optional feature.
  cxx::Ref_ptr<Gic::Msix_controller> _msix_ctrl;
  Pci_bridge_windows _windows;

  cxx::Ref_ptr<Vdev::Msi::Msi_src_factory> _msi_src_factory;
};

} } // namespace Vdev::Pci
