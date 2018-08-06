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

#include <cassert>
#include <vector>

#include <l4/l4virtio/virtqueue>

#include "device.h"
#include "ds_mmio_mapper.h"
#include "host_dt.h"
#include "ram_ds.h"
#include "vm_memmap.h"

inline L4virtio::Ptr<void>
l4_round_size(L4virtio::Ptr<void> p, unsigned char bits)
{ return L4virtio::Ptr<void>((p.get() + (1ULL << bits) - 1) & (~0ULL << bits)); }

class Vm_mem;

namespace Vmm {

class Ram_free_list
{
  friend class Vm_ram;
public:
  l4_addr_t base_address() const
  { return _freelist[0].start; }

  bool reserve_fixed(l4_addr_t start, l4_size_t size);
  bool reserve_back(l4_size_t size, l4_addr_t *start,
                    unsigned char page_shift = L4_PAGESHIFT);

  long load_file_to_back(Vm_ram *ram, char const *name,
                         L4virtio::Ptr<void> *start, l4_size_t *size);

private:
  void add_free_region(l4_addr_t start, l4_size_t size)
  { _freelist.push_back(Region::ss(start, size)); }

  std::vector<Region> _freelist;
};

/**
 * The memory device which manages the RAM available to the guest.
 */
class Vm_ram : public Vdev::Device
{
public:
  Vm_ram(l4_addr_t boot_offset)
  : _boot_offset(boot_offset)
  {}

  /**
   * Load the contents of the given dataspace into guest RAM.
   *
   * \param file  Dataspace to load from. The entire dataspace is loaded.
   * \param addr  Guest physical address to load the data space to.
   * \param sz    Number of bytes to copy.
   */
  void load_file(L4::Cap<L4Re::Dataspace> const &file,
                 L4virtio::Ptr<void> addr, l4_size_t sz) const
  {
    auto *r = find_region(addr.get(), 0);
    assert(r);

    r->load_file(file, addr, sz);
  }

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

  /**
   * Set up the RAM according to the configuration in the given device tree.
   *
   * \param dt               Device tree to scan. May be invalid, in which case
   *                         only a single region from the 'ram' dataspace is
   *                         set up.
   * \param memap            Geust memory map where to register the new region.
   * \param default_address  Address to map RAM to when no config is found
   *                         in the device tree.
   *
   * \return Free list of RAM that may be prefilled with custom content.
   *         At the moment the list contains all regions that are related to
   *         the first memory entry in the device tree.
   */
  Ram_free_list setup_from_device_tree(Vdev::Host_dt const &dt, Vm_mem *memmap,
                                       l4_addr_t default_address);

  void setup_default_region(Vdev::Host_dt const &dt, Guest *vmm,
                            l4_addr_t baseaddr);

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

  /**
   * Add a new RAM region.
   *
   * \param ds        Dataspace containing the RAM.
   * \param baseaddr  Guest physical start address of the dataspce.
   * \param ds_offset Offset into the dataspace where to start mapping.
   * \param size      Size of the area to map.
   * \param memap     Geust memory map where to register the new region.
   *
   * \return Index into _regions of the newly added region.
   */
  l4_size_t add_memory_region(L4::Cap<L4Re::Dataspace> ds,
                              l4_addr_t baseaddr, l4_addr_t ds_offset,
                              l4_size_t size, Vm_mem *memmap);

  long add_from_dt_node(Vm_mem *memmap, bool *found, Vdev::Dt_node const &node);
  void setup_default_region(Vdev::Host_dt const &dt, Vm_mem *memmap,
                            l4_addr_t baseaddr);

  std::vector<Vmm::Ram_ds> _regions;
  l4_addr_t _boot_offset;
};

}
