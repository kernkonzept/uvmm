/*
 * Copyright (C) 2015 Kernkonzept GmbH.
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

#include "device.h"
#include "device_tree.h"
#include "vm_ram.h"

namespace Vmm {

class Ram_ds : public Vm_ram, public virtual Vdev::Dev_ref
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
   * \param boot_offset Offset between guest physical and guest virtual address
   *                    during boot. Required for architectures that use a
   *                    special virtual boot memory layout instead of
   *                    simply exposing the physical memory.
   */
  explicit Ram_ds(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base = ~0UL,
                  l4_addr_t boot_offset = 0);

  virtual ~Ram_ds() = default;

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
            l4_size_t *sz = 0);

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
  L4virtio::Ptr<void>
  load_file(char const *name, L4virtio::Ptr<void> addr, l4_size_t *sz = 0);

  L4::Cap<L4Re::Dataspace> ram() const noexcept
  { return _ram; }

  /**
   * Compute the boot address of a guest physical pointer.
   */
  template <typename T>
  l4_addr_t boot_addr(L4virtio::Ptr<T> p) const
  { return p.get() + _boot_offset; }

  l4_addr_t boot_addr(l4_addr_t p) const noexcept
  { return p + _boot_offset; }

  /**
   * Computes the offset into the RAM given a boot virtual address.
   */
  l4_addr_t boot2ram(l4_addr_t p) const noexcept
  { return p - _boot_offset - vm_start(); }

  template <typename T>
  L4virtio::Ptr<T> boot2guest_phys(l4_addr_t p) const noexcept
  { return L4virtio::Ptr<T>(p - _boot_offset); }

  void setup_device_tree(Vdev::Device_tree dt)
  {
    auto mem_node = dt.path_offset("/memory");
    mem_node.set_reg_val(vm_start(), size());

    int addr_cells = mem_node.get_address_cells();
    mem_node.setprop("dma-ranges", _phys_ram, addr_cells);
    mem_node.appendprop("dma-ranges", vm_start(), addr_cells);
    mem_node.appendprop("dma-ranges", _phys_size, mem_node.get_size_cells());
  }

  void touch_rw()
  { l4_touch_rw((void *)local_start(), size()); }

private:
  L4::Cap<L4Re::Dataspace> _ram;
  L4Re::Util::Unique_cap<L4Re::Dma_space> _dma;
  l4_addr_t _boot_offset;
  L4Re::Dma_space::Dma_addr _phys_ram;
  l4_size_t _phys_size;
};

} // namespace
