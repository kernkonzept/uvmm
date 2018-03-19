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
#include <l4/cxx/ipc_server>
#include <l4/cxx/bitmap>
#include <l4/vbus/vbus>
#include <l4/re/dataspace>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>
#include <l4/re/inhibitor>
#include <l4/vbus/vbus_inhibitor.h>

#include "debug.h"
#include "irq.h"
#include "vm_memmap.h"
#include "ds_mmio_mapper.h"
#include "device.h"

namespace Vmm {

class Guest;

class Virt_bus : public cxx::Ref_obj
{
public:
  struct Devinfo
  {
    L4vbus::Device io_dev;
    l4vbus_device_t dev_info;
    cxx::Ref_ptr<Vdev::Device> proxy;
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
  explicit Virt_bus(L4::Cap<L4vbus::Vbus> bus)
  : _bus(bus)
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
        if (i.proxy == proxy)
          return &i;
      }
    return nullptr;
  }

  /**
   * Collect all resources available on the vbus
   *
   * \param devs  Reference to device lookup instance
   *
   * \retval true   Successfully collected all resources
   * \retval false  Failed to collect resources
   *
   * Iterate over all available devices on the vbus and collect
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
  L4::Cap<L4::Icu> _icu;
  std::vector<Devinfo> _devices;
  Irq_bitmap _irqs;
};

}
