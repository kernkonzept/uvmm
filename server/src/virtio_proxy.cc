/*
 * Copyright (C) 2016-2019 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *            Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/re/env>

#include "virtio_proxy.h"
#include "device_factory.h"

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    auto cap = Vdev::get_cap<L4virtio::Device>(node, "l4vmm,virtiocap");
    if (!cap)
      return nullptr;

    l4_uint64_t base, cfgsz;
    int res = node.get_reg_val(0, &base, &cfgsz);
    if (res < 0)
      {
#ifdef CONFIG_MMU
        Err().printf("Failed to read 'reg' from node %s: %s\n",
                     node.get_name(), node.strerror(res));
        throw L4::Runtime_error(-L4_EINVAL);
#else
        // This is not fatal. In case of no-MMU systems, all addresses are
        // globally unique. We preferrbly use the address of the config DS.
        base = ~0UL;
        cfgsz = L4_PAGESIZE;
#endif
      }

    int sz;
    unsigned nnq_id = -1U;
    auto const *prop = node.get_prop<fdt32_t>("l4vmm,no-notify", &sz);
    if (prop && sz > 0)
      nnq_id = fdt32_to_cpu(*prop);

    auto c = make_device<Virtio_proxy_mmio>(cap, static_cast<l4_size_t>(cfgsz),
                                            nnq_id, devs->ram().get());
    if (c->init_irqs(devs, node) < 0)
      return nullptr;

    c->register_irq(devs->vmm()->registry());
#ifndef CONFIG_MMU
    // No remapping possible: preferrably map to the physical address.
    l4_addr_t cfg_ds_start;
    l4_addr_t cfg_ds_end;
    L4Re::chksys(c->mmio_ds()->map_info(&cfg_ds_start, &cfg_ds_end),
                 "get config ds addr");

    if (res < 0)
        node.set_reg_val(cfg_ds_start, cfg_ds_end - cfg_ds_start + 1U);
    else if (base != cfg_ds_start)
      {
        auto warn = Dbg(Dbg::Dev, Dbg::Warn, "Virtio_proxy_mmio");
        warn.printf("Cannot map to requrested MMIO region"
                    " (requested: 0x%llx, actual: 0x%lx)."
                    " Guest performance will be impaired!\n",
                    base, cfg_ds_start);
      }
#endif

    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);
    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "proxy", &f };

}
