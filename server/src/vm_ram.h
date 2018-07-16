/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <vector>

#include <l4/l4virtio/virtqueue>

#include "device.h"
#include "ds_mmio_mapper.h"
#include "ram_ds.h"

inline L4virtio::Ptr<void>
l4_round_size(L4virtio::Ptr<void> p, unsigned char bits)
{ return L4virtio::Ptr<void>((p.get() + (1ULL << bits) - 1) & (~0ULL << bits)); }

class Vm_mem;

namespace Vmm {

/**
 * The memory device which manages the RAM available to the guest.
 */
class Vm_ram : public Vdev::Device
{
public:
  Vm_ram(l4_addr_t vm_base, l4_addr_t boot_offset, Vm_mem *memmap);

  /**
   * Add a new RAM region.
   *
   * \param ds        Dataspace containing the RAM.
   * \param baseaddr  Guest physical start address of the dataspce.
   * \param memap     Geust memory map where to register the new region.
   *
   */
  void add_memory_region(L4::Cap<L4Re::Dataspace> ds,
                         l4_addr_t baseaddr, Vm_mem *memmap);

  /**
   * Load the contents of the given dataspace into guest RAM.
   *
   * \param file     Dataspace to load from. The entire dataspace is loaded.
   * \param addr     Guest physical address to load the data space to.
   * \param[out] sz  (Optional) If not null, contains the number of bytes
   *                            copied on return.
   *
   * \return Points to the first address after the newly copied region.
   */
  L4virtio::Ptr<void> load_file(L4::Cap<L4Re::Dataspace> const &file,
                                L4virtio::Ptr<void> addr, l4_size_t *sz = 0) const
  {
    auto *r = find_region(addr.get(), 0);
    assert(r);

    return r->load_file(file, addr, sz);
  }

  /**
   * Load the contents of the given file into guest RAM.
   *
   * \param file     File to load.
   * \param addr     Guest physical address to load the data space to.
   * \param[out] sz  (Optional) If not null, contains the number of bytes
   *                            copied on return.
   *
   * \return Points to the first address after the newly copied region.
   */
  L4virtio::Ptr<void> load_file(char const *name, L4virtio::Ptr<void> addr,
                                l4_size_t *sz = 0) const;

  /**
   * Get a VMM-virtual pointer from a guest-physical address
   */
  template <typename T>
  T *guest2host(L4virtio::Ptr<T> p) const
  {
    auto *r = find_region(p.get(), 0);
    assert(r);

    return r->guest2host(p);
  }

  template <typename T>
  T *guest_region2host(l4_addr_t gaddr, l4_size_t size) const
  {
    auto *r = find_region(gaddr, size);
    if (!r)
      L4Re::chksys(-L4_ERANGE, "Guest address outside RAM region");

    return r->guest2host(L4virtio::Ptr<T>(gaddr));
  }

  void setup_device_tree(Vdev::Device_tree dt) const
  {
    int err = dt.remove_nodes_by_property("device_type", "memory");
    if (err < 0)
      {
        Err().printf("Unable to remove existing memory nodes: %s\n",
                     fdt_strerror(err));
        throw L4::Runtime_error(-L4_EINVAL);
      }

    for (auto const &r : _regions)
      {
        // "memory@" + 64bit hex address + '\0'
        char buf[7 + 16 + 1];
        std::snprintf(buf, sizeof(buf), "memory@%lx", r.vm_start());

        r.setup_device_tree(dt.first_node().add_subnode(buf));
      }
  }


  /**
   * Return the base address of the first registered RAM region.
   */
  l4_addr_t base_address() const
  {
    assert(!_regions.empty());
    return _regions.front().vm_start();
  }

  l4_size_t total_size() const
  {
    l4_size_t sz = 0;

    for (auto const &r : _regions)
      sz += r.size();

    return sz;
  }

  L4::Cap<L4Re::Dataspace> main_ds() const
  {
    assert(!_regions.empty());
    return _regions.front().ds();
  }

  /**
   * Compute the boot address of a guest physical pointer.
   */
  template <typename T>
  l4_addr_t guest_phys2boot(L4virtio::Ptr<T> p) const
  { return p.get() + _boot_offset; }

  l4_addr_t guest_phys2boot(l4_addr_t p) const noexcept
  { return p + _boot_offset; }

  template <typename T>
  L4virtio::Ptr<T> boot2guest_phys(l4_addr_t p) const
  {
    if (p < _boot_offset)
      L4Re::chksys(-L4_ERANGE, "Not a boot address");

    return L4virtio::Ptr<T>(p - _boot_offset);
  }

  void copy_from_ds(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                    L4virtio::Ptr<void> gp_addr, l4_size_t size) const
  {
    auto *r = find_region(gp_addr.get(), size);

    // XXX cannot handle copying into consecutive DS at the moment
    if (!r)
      L4Re::chksys(-L4_EINVAL, "Target address outside RAM while copying data to guest.");

    L4Re::chksys(r->ds()->copy_in(gp_addr.get() - r->vm_start(), ds, offset, size),
                 "Copying from dataspace into guest RAM.");
  }

  template<typename FUNC>
  void foreach_region(FUNC &&func) const
  {
    for (auto const &r : _regions)
      func(r);
  }

private:
  Ram_ds const *find_region(l4_addr_t addr, l4_size_t size) const
  {
    for (auto const &r : _regions)
      {
        if (addr >= r.vm_start() && addr - r.vm_start() + size <= r.size())
          return &r;
      }

    return nullptr;
  }

  std::vector<Vmm::Ram_ds> _regions;
  l4_addr_t _boot_offset;
};

}
