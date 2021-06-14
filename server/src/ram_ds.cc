/*
 * Copyright (C) 2018 Kernkonzept GmbH.
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
static Dbg trace(Dbg::Mmio, Dbg::Warn, "trace");

namespace Vmm {

long
Ram_ds::setup(Vmm::Guest_addr vm_base)
{
  Dbg info(Dbg::Mmio, Dbg::Info, "ram");

  _vm_start = vm_base;
  auto dma_cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dma_space>());

  auto *env = L4Re::Env::env();

  int err = l4_error(env->user_factory()->create(dma_cap.get()));
  if (err < 0)
    trace.printf("Cannot create DMA capability.\n");

  if (err >= 0)
    {
      err = dma_cap->associate(L4::Ipc::Cap<L4::Task>(),
                               L4Re::Dma_space::Phys_space);
      if (err < 0)
        trace.printf("Cannot access physical address space mappings.\n");
    }

  l4_size_t phys_size = size();
  L4Re::Dma_space::Dma_addr phys_ram = 0;

  if (err >= 0)
    err = dma_cap->map(L4::Ipc::make_cap(dataspace().get(), L4_CAP_FPAGE_RW),
                       offset(), &phys_size,
                       L4Re::Dma_space::Attributes::None,
                       L4Re::Dma_space::Bidirectional, &phys_ram);
  else
    phys_size = 0;

  bool cont = false;
  bool ident = false;

  if (err < 0 || phys_size < size())
    {
      if (_vm_start == Vmm::Guest_addr(Ram_base_identity_mapped))
        {
          warn.printf("Identity mapping requested but dataspace not contiguous.\n");
          return err < 0 ? err : -L4_ENOMEM;
        }
      warn.printf("RAM dataspace not contiguous, should not use DMA w/o IOMMU\n");
    }
  else
    {
      cont = true;
      if (_vm_start == Vmm::Guest_addr(Ram_base_identity_mapped))
        {
          _vm_start = Vmm::Guest_addr(phys_ram);
          ident = true;
        }
    }

  info.printf("RAM: @ 0x%lx size=0x%lx (%c%c)\n",
              _vm_start.get(), (l4_addr_t) size(),
              cont ? 'c' : '-',
              ident ? 'i' : '-');

  l4_addr_t local_start = this->local_start();
  info.printf("RAM: VMM mapping @ 0x%lx size=0x%lx\n", local_start, (l4_addr_t)size());

  _offset = local_start - _vm_start.get();
  info.printf("RAM: VM offset=0x%lx\n", _offset);

  if (err >= 0)
    _dma = cxx::move(dma_cap);

  _phys_ram = phys_ram;
  _phys_size = phys_size;

  return L4_EOK;
}


void
Ram_ds::load_file(L4::Cap<L4Re::Dataspace> const &file,
                  Vmm::Guest_addr addr, l4_size_t sz) const
{
  Dbg info(Dbg::Mmio, Dbg::Info, "file");

  info.printf("load: @ 0x%lx\n", addr.get());
  if (!file)
    L4Re::chksys(-L4_EINVAL);

  l4_addr_t offset = addr - _vm_start;

  if (addr < _vm_start || sz > size() || offset > size() - sz)
    {
      Err().printf("File does not fit into ram. "
                   "(Loading [0x%lx - 0x%lx] into area [0x%lx - 0x%llx])\n",
                   addr.get(), addr.get() + sz - 1,
                   _vm_start.get(), _vm_start.get() + size() - 1);
      L4Re::chksys(-L4_EINVAL);
    }

  info.printf("copy in: to offset 0x%lx-0x%lx\n", offset, offset + sz - 1);

  L4Re::chksys(dataspace()->copy_in(offset + this->offset(), file, 0, sz), "copy in");
}

} // namespace
