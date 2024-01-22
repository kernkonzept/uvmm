/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <vector>
#include <mutex>

#include <l4/cxx/ref_ptr>
#include <l4/cxx/bitmap>
#include <l4/vbus/vbus>
#include <l4/re/dataspace>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>

#include "debug.h"
#include "device.h"
#include "vbus_event.h"
#include "msi_allocator.h"

namespace Vmm {

class Virt_bus : public virtual Vdev::Dev_ref, public Vdev::Msi::Allocator
{
public:
  class Devinfo
  {
  public:
    L4vbus::Device io_dev() const
    { return _io_dev; }

    l4vbus_device_t dev_info() const
    { return _dev_info; }

    /*
     * Return the handler managing this device.
     */
    cxx::Ref_ptr<Vdev::Device> handler() const
    { return _handler; }

    /*
     * Set the handler managing this device.
     *
     * \param handler  The handler managing this device.
     *
     * A common pattern is to request the unassigned device from vbus and
     * assign it to the device implementation responsible for it:
     *
     *   auto *vdev = devs->vbus()->find_unassigned_device_by_hid(hid);
     *   ...
     *   auto c = Vdev::make_device<Device_impl>(...);
     *   vdev->set_handler(c);
     *
     * Note: If the device does not have a handler it will be assign to the
     * io_proxy (if configured).
     */
    void set_handler(cxx::Ref_ptr<Vdev::Device> const &handler)
    { _handler = handler; }

    /*
     * Check whether a device is already managed by a handler.
     *
     * \retval true   The device is already managed by a handler.
     * \retval false  The device is still free.
     */
    bool allocated() const
    { return _handler != nullptr; }

    Devinfo(L4vbus::Device io_dev, l4vbus_device_t dev_info)
    : _io_dev(io_dev), _dev_info(dev_info)
    {}

  private:
    L4vbus::Device _io_dev;
    l4vbus_device_t _dev_info;
    cxx::Ref_ptr<Vdev::Device> _handler;
  };

private:
  void collect_dev_resources(Virt_bus::Devinfo const &dev,
                             Vdev::Device_lookup const *devs);

  /**
   * Local MSI vector allocator with the vBUS ICU.
   */
  class Msi_bitmap
  {
    enum { Num_msis = 2048 };

  public:
    Msi_bitmap() : _max_available(0) { _m.clear_all(); }

    /**
     * Set the maximum number of available MSIs.
     *
     * \param max_avail  Number of MSIs supperted by the vBus ICU.
     */
    void set_msi_limit(unsigned max_avail)
    {
      // Only allow to set the limit once. It is only necessary once.
      assert(_max_available == 0);

      _max_available = max_avail;

      if (_max_available > Num_msis)
        Dbg().printf("Msi_bitmap: ICU supported number of MSIs is greater than "
                     "the number the allocator supports.\n");
    }

    long alloc()
    {
      std::lock_guard<std::mutex> lock(_mut);

      long num = _m.scan_zero();

      if (num < 0 || static_cast<unsigned>(num) >= _max_available)
        return -L4_ENOMEM;

      _m[num] = 1;
      return num;
    }

    void free(unsigned num)
    {
      std::lock_guard<std::mutex> lock(_mut);
      _m[num] = 0;
    }

    unsigned limit() const { return _max_available; }

  private:
    cxx::Bitmap<Num_msis> _m;
    unsigned _max_available;
    std::mutex _mut;
  };

  class Irq_bitmap
  {
    enum { Num_irqs = 2048 };
    cxx::Bitmap<Num_irqs * 2> _i;

  public:
    bool irq_present(unsigned irq)
    { return _i[irq * 2]; }

    bool irq_bound(unsigned irq)
    { return _i[irq * 2 + 1]; }

    void mark_irq_present(unsigned irq)
    { _i[irq * 2] = 1; }

    void mark_irq_bound(unsigned irq)
    {
      assert(irq_present(irq));
      _i[irq * 2 + 1] = 1;
    }

    void dump_irqs();
  };

public:
  explicit Virt_bus(L4::Cap<L4vbus::Vbus> bus, L4::Registry_iface *registry)
  : _bus(bus), _vbus_event(bus, registry)
  {
    if (!bus.is_valid())
      {
        Dbg(Dbg::Dev, Dbg::Warn, "vmbus")
          .printf("'vbus' capability not found. "
                  "Hardware access not possible for VM.\n");
        return;
      }

    L4vbus::Icu dev;
    L4Re::chksys(_bus->root().device_by_hid(&dev, "L40009"),
                 "requesting ICU");
    _icu = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Icu>(),
                        "allocate ICU cap");
    L4Re::chksys(dev.vicu(_icu), "requesting ICU cap");

    l4_icu_info_t info;
    L4Re::chksys(_icu->info(&info), "Request ICU info.");

    unsigned max_msi = 0;
    if (info.features & L4::Icu::F_msi)
      max_msi = info.nr_msis;

    _msis.set_msi_limit(max_msi);

    scan_bus();

    show_bus();
  }

  virtual ~Virt_bus() = default;

  bool available() const
  { return _bus.is_valid(); }

  bool irq_present(unsigned irq)
  { return _irqs.irq_present(irq); }

  bool irq_bound(unsigned irq)
  { return _irqs.irq_bound(irq); }

  void mark_irq_bound(unsigned irq)
  { return _irqs.mark_irq_bound(irq); }

  void dump_irqs()
  { _irqs.dump_irqs(); }

  Devinfo const *find_device(Vdev::Device const *handler) const
  {
    for (auto const &i: _devices)
      {
        if (i.handler() == handler)
          return &i;
      }
    return nullptr;
  }

  /// Allocate a MSI vector with the app global MSI allocator.
  long alloc_msi() override { return _msis.alloc(); }
  /// Free a previously allocated MSI vector.
  void free_msi(unsigned num) override { _msis.free(num); }
  /// Maximum number of MSIs at the ICU.
  unsigned max_msis() const override { return _msis.limit(); }

  /*
   * Lookup unassigned device by hid
   *
   * \param hid  The hid we are looking for.
   *
   * \return  Pointer to unallocated device, nullptr if device not present or
   *          already claimed by someone else. To claim the device, invoke
   *          Devinfo::set_handler().
   *
   * The method iterates over the vbus and tries to find a device matching hid.
   * If a device is found and not allocated it is returned. Otherwise we
   * continue the iteration.
   */
  Devinfo *find_unassigned_device_by_hid(char const *hid);

  /**
   * Collect all resources available on the vbus
   *
   * \param devs  Reference to device lookup instance
   *
   * \retval true   Successfully collected all resources
   * \retval false  Failed to collect resources
   *
   * Iterate over all unallocated devices on the vbus and collect available
   * resources. The function looks at memory and irq resources. Memory is
   * mapped and added to the memory map. Irqs are tracked in a bitmap and may
   * be bind later on (see irq_present(), irq_bound(), mark_irq_bound()).
   */
  void collect_resources(Vdev::Device_lookup const *devs);

  L4::Cap<L4Re::Dataspace> io_ds() const
  { return L4::cap_reinterpret_cast<L4Re::Dataspace>(_bus); }

  L4::Cap<L4vbus::Vbus> bus() const
  { return _bus; }

  L4::Cap<L4::Icu> icu() const override
  { return _icu; }

  static void print_resource(l4vbus_resource_t const &res,
                             const char *prefix = "");

  void show_bus();

private:
  void scan_bus();

  L4::Cap<L4vbus::Vbus> _bus;
  Vbus_event _vbus_event;
  L4::Cap<L4::Icu> _icu;
  std::vector<Devinfo> _devices;
  Irq_bitmap _irqs;
  Msi_bitmap _msis;
};

}
