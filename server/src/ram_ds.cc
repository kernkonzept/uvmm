/*
 * Copyright (C) 2015-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cassert>
#include <l4/re/env>
#include <l4/re/error_helper>

#include "debug.h"
#include "ram_ds.h"

static Dbg warn(Dbg::Mmio, Dbg::Warn, "ram");
static Dbg trace(Dbg::Mmio, Dbg::Trace, "ram");

namespace Vmm {

long
Ram_ds::setup(Vmm::Guest_addr vm_base, Vmm::Address_space_manager *as_mgr)
{
  Dbg info(Dbg::Mmio, Dbg::Info, "ram");

  _vm_start = vm_base;

  if (as_mgr->is_any_identity_mode())
    {
      l4_size_t phys_size = size();
      L4Re::Dma_space::Dma_addr phys_ram = 0;
      int err = as_mgr->get_phys_mapping(dataspace().get(), ds_offset(),
                                         &phys_ram, &phys_size);

      if (err < 0 || phys_size < size())
        {
          warn.printf(
            "Identity mapping requested, but dataspace not contiguous.\n");
          return err < 0 ? err : -L4_ENOMEM;
        }

      _vm_start = Vmm::Guest_addr(phys_ram);

      if (as_mgr->is_iommu_identity_mode())
        as_mgr->add_ram_iommu(_vm_start, local_start(), size());

      _phys_ram = phys_ram;
      _phys_size = phys_size;
    }
  else if (as_mgr->is_dma_offset_mode())
    {
      /**
       * While this code looks rather alike to the identity_mode case, the
       * semantics are quite different. The DMA address the as_mgr returns
       * can be used by the guest for device access, but it is not the host-
       * physical address corresponding to the given dataspace.
       */
      l4_size_t dma_size = size();
      L4Re::Dma_space::Dma_addr dma_addr = 0;
      int err = as_mgr->get_phys_mapping(dataspace().get(), ds_offset(),
                                         &dma_addr, &dma_size);

      if (err < 0 || dma_size < size())
        warn.printf("DMA offset mode requested, but dataspace not contiguous. "
                    "DMA usage not recommended.\n");

      _phys_ram = dma_addr;
      _phys_size = dma_size;
    }
  else if (as_mgr->is_iommu_mode())
    as_mgr->add_ram_iommu(vm_start(), local_start(), size());
  else
    info.printf("RAM not set up for DMA.\n");

  l4_addr_t local_start = this->local_start();
  info.printf("RAM: @ 0x%lx size=0x%lx\n", _vm_start.get(),
              static_cast<l4_addr_t>(size()));
  info.printf("RAM: VMM local mapping @ 0x%lx\n", local_start);

  _offset = local_start - _vm_start.get();
  info.printf("RAM: VM offset=0x%lx\n", _offset);

  return L4_EOK;
}


void
Ram_ds::load_file(L4::Cap<L4Re::Dataspace> const &file,
                  Vmm::Guest_addr addr, l4_size_t sz)
{
  Dbg info(Dbg::Mmio, Dbg::Info, "file");

  info.printf("load: @ 0x%lx\n", addr.get());
  if (!file)
    L4Re::throw_error(-L4_EINVAL, "File dataspace valid.");

  l4_addr_t offset = addr - _vm_start;

  if (addr < _vm_start || sz > size() || offset > size() - sz)
    {
      Err().printf("File does not fit into ram. "
                   "(Loading [0x%lx - 0x%lx] into area [0x%lx - 0x%llx])\n",
                   addr.get(), addr.get() + sz - 1,
                   _vm_start.get(), _vm_start.get() + size() - 1);
      L4Re::throw_error(-L4_EINVAL, "File fits into guest RAM.");
    }

  info.printf("copy in: to offset 0x%lx-0x%lx\n", offset, offset + sz - 1);

  int r = dataspace()->copy_in(offset + this->offset(), file, 0, sz);
  if (r != -L4_EINVAL)
    L4Re::chksys(r, "Copy file into guest RAM.");
  else
    {
      // Failure was due to different dataspace sources. Therefor the dataspace
      // manager cannot copy directly and we to do the copy ourselves.
      const L4Re::Env *e = L4Re::Env::env();
      char *src = 0;
      L4Re::chksys(e->rm()->attach(&src, sz,
                                   L4Re::Rm::F::Search_addr
                                   | L4Re::Rm::F::R, file),
                   "Attach file dataspace for reading.");
      memcpy(reinterpret_cast<char *>(local_start()) + offset, src, sz);
      L4Re::chksys(e->rm()->detach(src, 0),
                   "Detach file dataspace.");
    }
}

} // namespace
