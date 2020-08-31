/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/dataspace>
#include <l4/re/dma_space>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>
#include <l4/util/util.h>

#include <l4/l4virtio/virtqueue>

#include <cstdio>

#include "device.h"
#include "device_tree.h"
#include "ds_manager.h"
#include "mem_types.h"

namespace Vmm {

/**
 * A contiguous piece of RAM backed by a part of an L4 dataspace.
 */
class Ram_ds : public Vmm::Ds_manager
{
public:
  enum { Ram_base_identity_mapped = ~0UL };

  /**
   * Create a new RAM dataspace.
   *
   * \param ds       L4Re Dataspace that represents the RAM for the VM.
   * \param size     Size of the region (default: use dataspace size).
   * \param offset   Offset into the dataspace.
   */
  Ram_ds(L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap ds,
         l4_size_t size, l4_addr_t offset)
  : Ds_manager(ds, offset, size, L4Re::Rm::F::RWX,
               sizeof(l4_umword_t) == 8 && size >= Ram_hugepagesize
               ? Ram_hugepageshift : L4_SUPERPAGESHIFT)
  {}

  Ram_ds(Vmm::Ram_ds const &) = delete;
  Ram_ds(Vmm::Ram_ds &&) = default;
  ~Ram_ds() = default;

  /**
   * Set up the memory for DMA and host access.
   *
   * \param vm_base  Guest physical address where the RAM should be mapped.
   *                 If `Ram_base_identity_mapped`, use the host physical address
   *                 of the backing memory (required for DMA without IOMMU).
   */
  long setup(Vmm::Guest_addr vm_base);

  /**
   * Load the contents of the given dataspace into guest RAM.
   *
   * \param file  Dataspace to load from.
   * \param addr  Guest physical address to load the data space to.
   * \param sz    Number of bytes to copy.
   */
  void load_file(L4::Cap<L4Re::Dataspace> const &file,
                 Vmm::Guest_addr addr, l4_size_t sz) const;

  /**
   * Get a VMM-virtual pointer from a guest-physical address
   */
  l4_addr_t guest2host(Vmm::Guest_addr p) const noexcept
  { return p.get() + _offset; }

  L4::Cap<L4Re::Dataspace> ds() const noexcept
  { return dataspace().get(); }

  void dt_append_dmaprop(Vdev::Dt_node const &mem_node) const
  {
    auto parent = mem_node.parent_node();
    size_t addr_cells = mem_node.get_address_cells(parent);
    size_t size_cells = mem_node.get_size_cells(parent);
    mem_node.appendprop("dma-ranges", _phys_ram, addr_cells);
    mem_node.appendprop("dma-ranges", _vm_start.get(), addr_cells);
    mem_node.appendprop("dma-ranges", _phys_size, size_cells);
  }

  Vmm::Guest_addr vm_start() const noexcept { return _vm_start; }

  l4_addr_t local_start() { return local_addr<l4_addr_t>(); }
  l4_addr_t ds_offset() const noexcept { return offset(); }

  bool has_phys_addr() const noexcept { return _phys_size > 0; }

private:
  /// Offset between guest-physical and host-virtual address.
  l4_mword_t _offset;
  /// Guest-physical address of the mapped dataspace.
  Vmm::Guest_addr _vm_start;

  /// DMA space providing device access (if applicable).
  L4Re::Util::Unique_cap<L4Re::Dma_space> _dma;
  /// Host-physical address of the beginning of the mapped area (if applicable).
  L4Re::Dma_space::Dma_addr _phys_ram;
  /// Size of the contiguously mapped area from the beginning of the area.
  l4_size_t _phys_size;
};

} // namespace
