/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/env>
#include <l4/sys/meta>

#include "device_factory.h"
#include "mmio_space_handler.h"
#include "ds_mmio_mapper.h"
#include "guest.h"

static Dbg warn(Dbg::Dev, Dbg::Warn, "ipcmmio");

namespace Vdev
{
  /**
   * Device that proxies memory accesses to an external dataspace
   * or mmio space.
   *
   * If the capability supports the dataspace protocol, the memory
   * from the dataspace is mapped directly into the guest address space.
   * The region(s) defined in regs must be aligned to page boundaries.
   *
   * For the mmio space protocol, all accesses are forwarded via IPC.
   * Mmio spaces support arbitrary regs regions.
   *
   * Devie tree compatible: l4vmm,l4-mmio
   *
   * Device tree parameters:
   *   l4vmm,mmio-cap    - Capability that provides the dataspace or
   *                       mmio space interface. The capability is probed
   *                       for support of the two interfaces via the meta
   *                       protocol. If both interfaces are available
   *                       the dataspace protocol is used.
   *   regs              - Regions that cover the device.
   *   l4vmm,mmio-offset - Address in the dataspace/mmio space that
   *                       corresponds to the first base address in `regs`.
   *                       Default: 0.
   */
  struct Mmio_proxy : public Device
  {
    void init_device(Vdev::Device_lookup const *,
                     Vdev::Dt_node const &) override
    {}
  };
}

namespace {

using namespace Vdev;

class F : public Factory
{
public:
  cxx::Ref_ptr<Device> create(Device_lookup const *devs,
                              Dt_node const &node) override
  {
    char const *capname = node.get_prop<char>("l4vmm,mmio-cap", nullptr);

    if (!capname)
      {
        warn.printf("l4vmm,mmio device has no l4vmm,mmio-cap property.\n");
        return nullptr;
      }

    auto cap = L4Re::Env::env()->get_cap<void>(capname);

    if (!cap)
      {
        warn.printf("Capability '%s' not found.\n", capname);
        return nullptr;
      }

    auto dscap = L4::cap_dynamic_cast<L4Re::Dataspace>(cap);
    if (dscap)
      {
        register_mmio_regions<Ds_handler>(dscap, devs, node);
        return Vdev::make_device<Mmio_proxy>();
      }

    auto mmcap = L4::cap_dynamic_cast<L4Re::Mmio_space>(cap);
    if (mmcap)
      {
        register_mmio_regions<Mmio_space_handler>(mmcap, devs, node);
        return Vdev::make_device<Mmio_proxy>();
      }

    warn.printf("No known IPC protocol supported.\n");
    return nullptr;
  }

private:
  template <typename HANDLERTYPE, typename CAPTYPE>
  void register_mmio_regions(L4::Cap<CAPTYPE> cap, Device_lookup const *devs,
                             Dt_node const &node)
  {
    l4_uint64_t regbase, base, size;
    l4_uint64_t offset = 0;
    int propsz;
    auto *prop = node.get_prop<fdt32_t>("l4vmm,mmio-offset", &propsz);

    if (prop)
      offset = node.get_prop_val(prop, propsz, true);

    if (node.get_reg_val(0, &regbase, &size) < 0)
      L4Re::chksys(-L4_EINVAL, "reg property not found or invalid");

    size_t index = 0;
    while (node.get_reg_val(index, &base, &size) >= 0)
      {
        auto handler = Vdev::make_device<HANDLERTYPE>(cap, 0, size,
                                                      offset + (base - regbase));
        devs->vmm()->register_mmio_device(handler, node, index);
        ++index;
      }
  }
};


static F f;
static Device_type t = { "l4vmm,l4-mmio", nullptr, &f };

}

