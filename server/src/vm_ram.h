/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
/*
 * Copyright (C) 2015-2016, 2018-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>
#include <vector>

#include "device.h"
#include "ds_mmio_mapper.h"
#include "host_dt.h"
#include "mem_types.h"
#include "ram_ds.h"
#include "vm_memmap.h"
#include "monitor/vm_ram_cmd_handler.h"
#include "address_space_manager.h"

class Vm_mem;

namespace Vmm {

class Ram_free_list
{
  friend class Vm_ram;

public:
  /**
   * Return the first available address in the free list.
   *
   * This is the first address found in the order that regions were originally
   * added to the list and that is still available.
   */
  Vmm::Guest_addr first_free_address() const
  { return _freelist[0].start; }

  bool reserve_fixed(Vmm::Guest_addr start, l4_size_t size);
  bool reserve_back(l4_size_t size, Vmm::Guest_addr *start,
                    unsigned char page_shift = L4_PAGESHIFT,
                    Vmm::Guest_addr upper_limit = Vmm::Guest_addr(~0UL));

  long load_file_to_back(Vm_ram *ram, char const *name,
                         Vmm::Guest_addr *start, l4_size_t *size);

private:
  void add_free_region(Vmm::Guest_addr start, l4_size_t size)
  { _freelist.push_back(Region::ss(start, size, Region_type::Ram)); }

  std::vector<Region> _freelist;
};

/**
 * The memory device which manages the RAM available to the guest.
 */
class Vm_ram
: public Vdev::Device,
  public Monitor::Vm_ram_cmd_handler<Monitor::Enabled, Vm_ram>
{
  friend Vm_ram_cmd_handler<Monitor::Enabled, Vm_ram>;

public:
  Vm_ram(l4_addr_t boot_offset)
  : _boot_offset(boot_offset),
    _as_mgr(Vdev::make_device<Vmm::Address_space_manager>())
  {}

  /**
   * Load the contents of the given dataspace into guest RAM.
   *
   * \param file  Dataspace to load from. The entire dataspace is loaded.
   * \param addr  Guest physical address to load the data space to.
   * \param sz    Number of bytes to copy.
   */
  void load_file(L4::Cap<L4Re::Dataspace> const &file,
                 Vmm::Guest_addr addr, l4_size_t sz) const
  {
    auto r = find_region(addr, 0);
    if (!r)
      L4Re::chksys(-L4_ENOENT, "Guest region found");

    r->load_file(file, addr, sz);
  }

  /**
   * Get a VMM-virtual pointer from a guest-physical address.
   */
  template <typename T>
  T guest2host(Vmm::Guest_addr p) const
  {
    auto r = find_region(p, 0);
    if (!r)
      L4Re::chksys(-L4_ENOENT, "Guest address outside RAM");

    return reinterpret_cast<T>(r->guest2host(p));
  }

  /**
   * Get a VMM-virtual pointer for the start of the given region.
   *
   * An exception is thrown if the region is not completely contained in
   * one of the RAM areas.
   */
  template <typename T>
  T guest2host(Region region) const
  {
    auto r = find_region(region.start, region.end - region.start + 1);
    if (!r)
      L4Re::chksys(-L4_ERANGE, "Guest address outside RAM region");

    return reinterpret_cast<T>(r->guest2host(region.start));
  }

  /**
   * Set up the RAM according to the configuration in the given device tree.
   *
   * \param dt               Device tree to scan. May be invalid, in which case
   *                         only a single region from the 'ram' dataspace is
   *                         set up.
   * \param memap            Guest memory map where to register the new region.
   * \param default_address  Address to map RAM to when no config is found
   *                         in the device tree.
   *
   * \return Free list of RAM that may be prefilled with custom content.
   *         At the moment the list contains all regions that are related to
   *         the first memory entry in the device tree.
   */
  Ram_free_list setup_from_device_tree(Vdev::Host_dt const &dt, Vm_mem *memmap,
                                       Vmm::Guest_addr default_address);

  /**
   * Move the device tree into guest RAM.
   *
   * \param free_list  List of usable RAM regions. The device tree will be
   *                   copied to the first available area at the end of this
   *                   list.
   * \param dt         Host device tree, to be discarded after having been
   *                   moved to RAM.
   *
   * \return Boot address of the begining of the device tree.
   */
  l4_addr_t move_in_device_tree(Ram_free_list *free_list, Vdev::Host_dt &&dt);

  /**
   * Compute the boot address of a guest physical pointer.
   */
  l4_addr_t guest_phys2boot(Vmm::Guest_addr p) const noexcept
  { return p.get() + _boot_offset; }

  Vmm::Guest_addr boot2guest_phys(l4_addr_t p) const
  {
    if (p < _boot_offset)
      L4Re::chksys(-L4_ERANGE, "Not a boot address");

    return Vmm::Guest_addr(p - _boot_offset);
  }

  void copy_from_ds(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                    Vmm::Guest_addr gp_addr, l4_size_t size) const
  {
    auto r = find_region(gp_addr, size);

    // XXX cannot handle copying into consecutive DS at the moment
    if (!r)
      L4Re::chksys(-L4_EINVAL, "Target address outside RAM while copying data to guest.");

    L4Re::chksys(r->ds()->copy_in(gp_addr.get() - r->vm_start().get(),
                                  ds, offset, size),
                 "Copying from dataspace into guest RAM.");
  }

  template<typename FUNC>
  void foreach_region(FUNC &&func) const
  {
    for (auto const &r : _regions)
      func(*r.get());
  }

  Vmm::Address_space_manager *as_mgr() const { return _as_mgr.get(); }

  /**
   * Add a new RAM region.
   *
   * \param ds        Dataspace containing the RAM.
   * \param baseaddr  Guest physical start address of the dataspce.
   * \param ds_offset Offset into the dataspace where to start mapping.
   * \param size      Size of the area to map.
   * \param memap     Guest memory map where to register the new region.
   * \param flags     Access rights for the memory region.
   *
   * \return Index into _regions of the newly added region.
   */
  l4_size_t add_memory_region(L4::Cap<L4Re::Dataspace> ds,
                              Vmm::Guest_addr baseaddr, l4_addr_t ds_offset,
                              l4_size_t size, Vm_mem *memmap,
                              L4Re::Rm::Region_flags flags = L4Re::Rm::F::RWX);

private:
  cxx::Ref_ptr<Ram_ds> find_region(Vmm::Guest_addr addr, l4_size_t size) const
  {
    for (auto const &r : _regions)
      {
        if (addr >= r->vm_start() && addr - r->vm_start() + size <= r->size())
          return r;
      }

    return nullptr;
  }

  long add_from_dt_node(Vm_mem *memmap, bool *found, Vdev::Dt_node const &node);
  void setup_default_region(Vdev::Host_dt const &dt, Vm_mem *memmap,
                            Vmm::Guest_addr baseaddr);

  std::vector<cxx::Ref_ptr<Vmm::Ram_ds>> _regions;
  l4_addr_t _boot_offset;
  cxx::Ref_ptr<Vmm::Address_space_manager> _as_mgr;
};

}
