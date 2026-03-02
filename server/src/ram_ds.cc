/*
 * Copyright (C) 2015-2025 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <cassert>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/util/printf_helpers.h>

#include "debug.h"
#include "ram_ds.h"

static Dbg warn(Dbg::Mmio, Dbg::Warn, "ram");
static Dbg trace(Dbg::Mmio, Dbg::Trace, "ram");

namespace Vmm {

int
Ram_ds::setup(Vmm::Guest_addr vm_base, Vmm::Guest_addr vm_limit,
              Vmm::Address_space_manager *as_mgr, Dma_mode dma_mode)
{
  Dbg info(Dbg::Mmio, Dbg::Info, "ram");

  _vm_start = vm_base;
  _dma_start = vm_base.get();

  if (dma_mode == Dma_mode::Congruent || dma_mode == Dma_mode::Incongruent)
    {
      L4Re::Dma_space::Dma_size phys_size = size();
      int err = as_mgr->add_ram(dataspace().get(), ds_offset(), &_dma_start,
                                &phys_size, vm_limit.get());
      if (err < 0)
        return err;

      // If reserved DMA regions are encountered, we might not be able to map
      // the whole size. The Vm_ram setup code will try again with the
      // remainder.
      set_size(phys_size);
    }

  if (dma_mode == Dma_mode::Congruent)
    _vm_start = Vmm::Guest_addr(_dma_start);

  l4_addr_t local_start = this->local_start();
  char sz[64];
  l4util_human_readable_size(sz, sizeof(sz), size());
  info.printf("RAM: @ 0x%lx size=0x%lx (%s)\n", _vm_start.get(),
              static_cast<l4_addr_t>(size()), sz);
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
      // Failure was due to different dataspace sources. Therefore the dataspace
      // manager cannot copy directly and we have to do the copy ourselves.
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
