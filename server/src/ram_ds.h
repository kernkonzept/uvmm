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

#include <l4/l4virtio/virtqueue>

#include "vm_ram.h"

namespace Vmm {

class Ram_ds : public Vm_ram
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

  L4virtio::Ptr<void>
  load_file(char const *name, l4_addr_t offset, l4_size_t *_size = 0);

  L4virtio::Ptr<void>
  load_file(char const *name, L4virtio::Ptr<void> addr, l4_size_t *_size = 0)
  { return load_file(name, addr.get() - _vm_start, _size); }

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

  void dma_area(l4_addr_t *phys_base, l4_size_t *phys_size) const
  {
    *phys_base = _phys_ram;
    *phys_size = _phys_size;
  }

private:
  L4::Cap<L4Re::Dataspace> _ram;
  L4Re::Util::Auto_cap<L4Re::Dma_space>::Cap _dma;
  l4_addr_t _boot_offset;
  L4Re::Dma_space::Dma_addr _phys_ram;
  l4_size_t _phys_size;
};

} // namespace
