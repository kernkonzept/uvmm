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

#include <l4/cxx/ref_ptr>
#include <l4/cxx/bitmap>
#include <l4/vbus/vbus>
#include <l4/re/dataspace>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>

#include "debug.h"
#include "device.h"
#include "vbus_event.h"

namespace Vmm {

class Virt_bus : public virtual Vdev::Dev_ref
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
     * Return the proxy managing this device.
     */
    cxx::Ref_ptr<Vdev::Device> proxy() const
    { return _proxy; }

    /*
     * Set the proxy managing this device.
     *
     * \param proxy  The proxy managing this device.
     */

    void set_proxy(cxx::Ref_ptr<Vdev::Device> const &proxy)
    { _proxy = proxy; }

    /*
     * Check whether a device is already managed by a proxy.
     *
     * \retval true   The device is already managed by a proxy.
     * \retval false  The device is still free.
     */
    bool allocated() const
    { return _proxy != nullptr; }

    Devinfo(L4vbus::Device io_dev, l4vbus_device_t dev_info)
    : _io_dev(io_dev), _dev_info(dev_info)
    {}

  private:
    L4vbus::Device _io_dev;
    l4vbus_device_t _dev_info;
    cxx::Ref_ptr<Vdev::Device> _proxy;
  };

private:
  void collect_dev_resources(Virt_bus::Devinfo const &dev,
                             Vdev::Device_lookup const *devs);

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

    scan_bus();
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

  Devinfo const *find_device(Vdev::Device const *proxy) const
  {
    for (auto const &i: _devices)
      {
        if (i.proxy() == proxy)
          return &i;
      }
    return nullptr;
  }

  /*
   * Lookup unassigned device by hid
   *
   * \param hid  The hid we are looking for.
   *
   * \return  Pointer to unallocated device, nullptr if device not present or
   *          already claimed by someone else. To claim the device, invoke
   *          Devinfo::set_proxy().
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

  L4::Cap<L4::Icu> icu() const
  { return _icu; }

private:
  void scan_bus();

  L4::Cap<L4vbus::Vbus> _bus;
  Vbus_event _vbus_event;
  L4::Cap<L4::Icu> _icu;
  std::vector<Devinfo> _devices;
  Irq_bitmap _irqs;
};

}
