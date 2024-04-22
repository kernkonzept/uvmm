/*
 * Copyright (C) 2024 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include "debug.h"
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <l4/re/dataspace>
#include "guest.h"

#include <vector>

namespace Vdev
{

/**
 * Memory pool for foreign guest memory used by virtio device proxy devices.
 *
 * If multiple virtio device proxy devices from the same guest are used in one
 * uvmm instance we only want to map the foreign guest memory once. Therefore
 * every virtio device proxy device needs to be registered with one virtio
 * memory pool. The virtio memory pool describes a region in guest RAM where
 * the foreign guest memory will be mapped to. Multiple guests can use the same
 * memory pool. However, multiple memory pools are also possible.
 *
 * A device tree entry needs to look like this:
 *
 * viodev_mp: viodev_mp@1600000000 {
 *   compatible = "l4vmm,mempool";
 *   reg = <0x16 0x0 0x20 0x0>;
 * };
 *
 * A virtio device proxy device needs to refer to the pool it wants to use,
 * like this:
 *
 * viodev@80000000 {
 *   compatible = "virtio-dev,mmio";
 *   ...
 *   l4vmm,mempool = <&viodev_mp>;
 *   ...
 * }
 *
 * Note, the memory pool node has to be defined before any other nodes using
 * it.
 */

class Virtio_device_mem_pool : public Device
{
public:
  Virtio_device_mem_pool(Vdev::Device_lookup *devs,
                         l4_uint64_t phys, l4_uint64_t size)
  : _devs(devs), _phys(phys), _size(size)
  {}

  Vmm::Region register_ds(L4::Cap<L4Re::Dataspace> const &ds,
                          l4_uint64_t ds_base, l4_umword_t offset, l4_umword_t sz)
  {
    // Check if we know this region already
    for (auto const &c: _regions)
      if (c.ds_base == ds_base && c.offset == offset && c.sz == sz &&
          L4Re::Env::env()->task()->cap_equal(c.ds.get(), ds).label() == 1)
        return c.region;

    // This is a very simple memory manager. It always adds a new region behind
    // the last known region. It does not look at any requirements for
    // alignment or tries to fill holes. As we do not support unmapping right
    // now, this is ok. Should be easily possible to convert this to a stl map
    // like tree. See vm_memmap.* for inspiration.
    Vmm::Guest_addr new_mapping = _phys;
    if (!_regions.empty())
      {
        new_mapping = _regions.back().region.end + 1;
        if (new_mapping + sz - 1 > _phys + _size - 1)
          L4Re::throw_error(-L4_EINVAL, "New region doesn't fit into mempool");
      }
    info.printf("Add region: 0x%lx:0x%lx\n", new_mapping.get(), sz);

    auto region = Vmm::Region::ss(new_mapping, sz, Vmm::Region_type::Virtual);
    auto ds_mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Virtio_mem_pool", ds,
                                                     offset, sz);
    _devs->vmm()->add_mmio_device(region,
                                  Vdev::make_device<Ds_handler>(ds_mgr));

    if (_devs->ram()->as_mgr()->is_iommu_mode())
      _devs->ram()->as_mgr()->add_ram_iommu(region.start,
                                            ds_mgr->local_addr<l4_addr_t>(),
                                            sz);

    _regions.emplace_back(ds, region, ds_base, offset, sz);

    return region;
  }

private:
  Dbg info = {Dbg::Dev, Dbg::Info, "viodev-mp"};

  Vdev::Device_lookup *_devs;

  struct GuestMemRegion
  {
    GuestMemRegion(L4::Cap<L4Re::Dataspace> const &ds, Vmm::Region const &region,
                   l4_uint64_t ds_base, l4_umword_t offset, l4_umword_t sz)
    : ds(ds),
      region(region),
      ds_base(ds_base),
      offset(offset),
      sz(sz)
    {}

    L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap ds;
    Vmm::Region region;
    l4_uint64_t ds_base;
    l4_umword_t offset;
    l4_umword_t sz;
  };

  std::vector<GuestMemRegion> _regions;
  Vmm::Guest_addr _phys;
  l4_uint64_t _size;
};

}
