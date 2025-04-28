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
 * \code{.dtb}
 *   viodev_mp: viodev_mp@1600000000 {
 *       compatible = "l4vmm,mempool";
 *       reg = <0x16 0x0 0x20 0x0>;
 *   };
 * \endcode
 *
 * A virtio device proxy device needs to refer to the pool it wants to use,
 * like this:
 *
 * \code{.dtb}
 *   viodev@80000000 {
 *       compatible = "virtio-dev,mmio";
 *       ...
 *       l4vmm,mempool = <&viodev_mp>;
 *       ...
 *   }
 * \endcode
 *
 * Note, the memory pool node has to be defined before any other nodes using
 * it.
 */

/**
 * Simple region map.
 *
 * Template storage class for managing a memory area. It is possible to
 * add/remove regions of any size. The class tries to automatically find a
 * range where the new region will fit. When a region is removed that range is
 * available for new use again.
 */
template <typename T>
class Region_map
{
public:
  using Tree = std::map<Vmm::Region, T>;
  using Iterator = typename Tree::iterator;
  using Const_iterator = typename Tree::const_iterator;

  Region_map(l4_addr_t base, l4_size_t size)
  : _base(base),
    _end(_base + size - 1)
  {}

  Iterator begin()
  { return _map.begin(); }

  Iterator end()
  { return _map.end(); }

  Const_iterator begin() const
  { return _map.begin(); }

  Const_iterator end() const
  { return _map.end(); }

  Vmm::Region const *add_region(l4_size_t size, T const &data,
                                unsigned char align = L4_PAGESHIFT)
  {
    auto addr = find_free(size, align);
    if (addr != L4_INVALID_ADDR)
      {
        const auto &[it, inserted] =_map.insert({region(addr, size), data});
        if (inserted)
          return &it->first;
      }

    return nullptr;
  }

  void del_region(Vmm::Region const &region)
  {
    auto it = _map.find(region);
    if (it != _map.end())
      del_region(it);
  }

  void del_region(Iterator it)
  { _map.erase(it); }

  Iterator find(T const &data)
  {
    for (auto it = _map.begin(); it != _map.end(); ++it)
      if (it->second == data)
        return it;

    return end();
  }

  Const_iterator find(T const &o) const
  {
    for (auto it = _map.begin(); it != _map.end(); ++it)
      if (it->second == o)
        return it;

    return end();
  }

  Iterator find(Vmm::Region const &o)
  { return _map.find(o); }

  Const_iterator find(Vmm::Region const &o) const
  { return _map.find(o); }

  void dump(std::string const &name, Dbg::Verbosity l) const
  {
    Dbg d(Dbg::Dev, l, name.c_str());
    if (d.is_active())
      {
        d.printf("%s:\n", name.c_str());
        for (const auto& n : _map)
          d.printf(" [%8lx:%8lx]\n",
                   n.first.start.get(), n.first.end.get());
      }
  }

private:
  static constexpr Vmm::Region region(l4_addr_t start, l4_size_t size)
  {
    return Vmm::Region::ss(Vmm::Guest_addr(start), size,
                           Vmm::Region_type::Virtual);
  }

  l4_addr_t find_free(l4_size_t size, unsigned char align)
  {
    if (size == 0)
      return L4_INVALID_ADDR;

    l4_addr_t addr = l4_round_size(_base, align);

    for (;;)
      {
        if (addr >= _end)
          break;

        if (addr + size - 1 > _end)
          break;

        auto it = _map.find(region(addr, size));
        if (it == _map.end())
          return addr;

        addr = l4_round_size(it->first.end.get() + 1, align);
      }

    return L4_INVALID_ADDR;
  }

  l4_addr_t const _base;
  l4_addr_t const _end;
  Tree _map;
};

class Virtio_device_mem_pool : public Device
{
public:
  Virtio_device_mem_pool(Vdev::Device_lookup *devs,
                         l4_uint64_t phys, l4_uint64_t size)
  : _devs(devs),
    _region_map(phys, size)
  {}

  Vmm::Region const *register_ds(L4::Cap<L4Re::Dataspace> const &ds,
                                 l4_uint64_t ds_base, l4_umword_t offset,
                                 l4_umword_t sz)
  {
    Ds_item mr(ds, ds_base, offset, sz);

    // Check if we know this region already.
    // If found, we increase the ref count, so it doesn't go away.
    auto it =_region_map.find(mr);
    if (it != _region_map.end())
      {
        it->second.take_ref();
        return &it->first;
      }

    // Not found, find/add new one.
    Vmm::Region const *r = _region_map.add_region(sz, mr);
    if (!r)
      return r;

    info.printf("Add region: 0x%lx:0x%lx\n", r->start.get(), sz);

    auto ds_mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Virtio_mem_pool", ds,
                                                     offset, sz);
    _devs->vmm()->add_mmio_device(*r,
                                  Vdev::make_device<Ds_handler>(ds_mgr));

    if (_devs->ram()->as_mgr()->is_iommu_mode() ||
        _devs->ram()->as_mgr()->is_iommu_identity_mode())
      _devs->ram()->as_mgr()->add_ram_iommu(r->start,
                                            ds_mgr->local_addr<l4_addr_t>(),
                                            sz);
    return r;
  }

  void drop_region(l4_uint64_t phys, l4_uint64_t size)
  {
    auto const region = Vmm::Region::ss(Vmm::Guest_addr(phys),
                                        size, Vmm::Region_type::Virtual);
    // If this is the last user of the region, remove it.
    auto it = _region_map.find(region);
    if (it != _region_map.end() && !it->second.drop_ref())
      {
        // Remove iommu entry if necessary
        if (_devs->ram()->as_mgr()->is_iommu_mode())
          _devs->ram()->as_mgr()->del_ram_iommu(region.start, region.size());
        // Delete vmm mmio device + mappings
        _devs->vmm()->del_mmio_device(region);
        // Remove the region from our virtual region map
        _region_map.del_region(it);
      }
  }

private:
  Dbg info = {Dbg::Dev, Dbg::Info, "viodev-mp"};

  Vdev::Device_lookup *_devs;

  struct Ds_item
  {
    Ds_item(L4::Cap<L4Re::Dataspace> const &ds,
            l4_uint64_t ds_base, l4_umword_t offset, l4_umword_t sz)
    : _ref(1),
      _ds(ds),
      _ds_base(ds_base),
      _offset(offset),
      _sz(sz)
    {}

    friend bool operator == (Ds_item const &l, Ds_item const &r) noexcept
    {
      return l._ds_base == r._ds_base && l._offset == r._offset
        && l._sz == r._sz
        && L4Re::Env::env()->task()->cap_equal(l._ds, r._ds).label() == 1;
    }

    void take_ref()
    { ++_ref; }

    bool drop_ref()
    { return !!--_ref; }

  private:
    l4_uint64_t _ref;
    L4::Cap<L4Re::Dataspace> _ds;
    l4_uint64_t _ds_base;
    l4_umword_t _offset;
    l4_umword_t _sz;
  };

  Region_map<Ds_item> _region_map;
};

}
