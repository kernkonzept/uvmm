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

namespace Vmm {

/**
 * A continuous piece of RAM backed by a part of an L4 dataspace.
 */
class Ram_ds
{
public:
  enum { Ram_base_identity_mapped = ~0UL };

  /**
   * Create a new RAM dataspace.
   *
   * \param ram         L4Re Dataspace that represents the RAM for the VM.
   * \param vm_base     Guest physical address where the RAM should be mapped.
   *                    If ~0UL, use the host physical address of the
   *                    backing memory (required for DMA without IOMMU).
   */
  explicit Ram_ds(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base = ~0UL);

  Ram_ds(Vmm::Ram_ds const &) = delete;
  Ram_ds(Vmm::Ram_ds &&) = default;
  ~Ram_ds() = default;

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
  L4virtio::Ptr<void>
  load_file(L4::Cap<L4Re::Dataspace> const &file, L4virtio::Ptr<void> addr,
            l4_size_t *sz) const;

  /**
   * Get a VMM-virtual pointer from a guest-physical address
   */
  template <typename T>
  T *guest2host(L4virtio::Ptr<T> p) const
  { return (T*)(p.get() + _offset); }

  L4::Cap<L4Re::Dataspace> ds() const noexcept
  { return _ds; }

  void setup_device_tree(Vdev::Dt_node const &mem_node) const
  {
    mem_node.setprop_string("device_type", "memory");
    mem_node.set_reg_val(vm_start(), size());

    int addr_cells = mem_node.get_address_cells();
    mem_node.setprop("dma-ranges", _phys_ram, addr_cells);
    mem_node.appendprop("dma-ranges", vm_start(), addr_cells);
    mem_node.appendprop("dma-ranges", _phys_size, mem_node.get_size_cells());
  }

  l4_addr_t vm_start() const noexcept { return _vm_start; }
  l4_size_t size() const noexcept { return _size; }
  l4_addr_t local_start() const noexcept { return _local_start; }

private:
  /// Offset between guest-physical and host-virtual address.
  l4_mword_t _offset;
  /// uvmm local address where the dataspace has been mapped.
  l4_addr_t _local_start;
  /// Guest-physical address of the mapped dataspace.
  l4_addr_t _vm_start;
  /// Size of the mapped area.
  l4_size_t _size;

  /// Backing dataspace for the RAM area.
  L4::Cap<L4Re::Dataspace> _ds;
  /// DMA space providing device access (if applicable).
  L4Re::Util::Unique_cap<L4Re::Dma_space> _dma;
  /// Host-physical address of the beginning of the mapped area (if applicable).
  L4Re::Dma_space::Dma_addr _phys_ram;
  /// Size of the continiously mapped area from the beginning of the area.
  l4_size_t _phys_size;
};

} // namespace
