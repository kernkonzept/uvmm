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

namespace Vmm {

Ram_ds::Ram_ds(L4::Cap<L4Re::Dataspace> ds, l4_addr_t vm_base)
: _ds(ds)
{
  Dbg info(Dbg::Mmio, Dbg::Info, "ram");

  _vm_start = vm_base;
  _size = ds->size();
  auto dma_cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dma_space>());

  auto *env = L4Re::Env::env();

  int err = l4_error(env->user_factory()->create(dma_cap.get()));

  if (err >= 0)
    err = dma_cap->associate(L4::Ipc::Cap<L4::Task>(L4::Cap<void>::Invalid),
                             L4Re::Dma_space::Phys_space);

  l4_size_t phys_size = _size;
  L4Re::Dma_space::Dma_addr phys_ram = 0;

  if (err >= 0)
    err = dma_cap->map(L4::Ipc::make_cap(ds, L4_CAP_FPAGE_RW),
                       0, &phys_size,
                       L4Re::Dma_space::Attributes::None,
                       L4Re::Dma_space::Bidirectional, &phys_ram);
  else
    phys_size = 0;

  bool cont = false;
  bool ident = false;

  if (err < 0 || phys_size < _size)
    {
      Dbg warn(Dbg::Mmio, Dbg::Warn, "ram");
      warn.printf("RAM dataspace not contiguous, should not use DMA w/o IOMMU\n");
      if (err >= 0 && _vm_start == Ram_base_identity_mapped)
        {
          _vm_start = phys_ram;
          ident = true;
        }
    }
  else
    {
      cont = true;
      if (_vm_start == Ram_base_identity_mapped)
        {
          _vm_start = phys_ram;
          ident = true;
        }
    }

  info.printf("RAM: @ 0x%lx size=0x%lx (%c%c)\n",
              _vm_start, (l4_addr_t) _size, cont ? 'c' : '-', ident ? 'i' : '-');

  _local_start = 0;
  L4Re::chksys(env->rm()->attach(&_local_start, _size,
                                 L4Re::Rm::Search_addr | L4Re::Rm::Eager_map,
                                 L4::Ipc::make_cap_rw(ds), 0,
                                 L4_SUPERPAGESHIFT));
  info.printf("RAM: VMM mapping @ 0x%lx size=0x%lx\n", _local_start, (l4_addr_t)_size);

  assert(_vm_start != ~0UL);

  _offset = _local_start - _vm_start;
  info.printf("RAM: VM offset=0x%lx\n", _offset);

  if (err >= 0)
    _dma = cxx::move(dma_cap);

  _phys_ram = phys_ram;
  _phys_size = phys_size;
}


L4virtio::Ptr<void>
Ram_ds::load_file(L4::Cap<L4Re::Dataspace> const &file,
                  L4virtio::Ptr<void> addr, l4_size_t *sz) const
{
  Dbg info(Dbg::Mmio, Dbg::Info, "file");

  info.printf("load: @ 0x%llx\n", addr.get());
  if (!file)
    L4Re::chksys(-L4_EINVAL);

  l4_addr_t offset = addr.get() - _vm_start;
  l4_size_t fsize = file->size();

  if (addr.get() < _vm_start || offset >= size() || offset + fsize >= size())
    {
      Err().printf("File does not fit into ram\n");
      L4Re::chksys(-L4_EINVAL);
    }

  info.printf("copy in: to offset 0x%lx-0x%lx\n", offset, offset + fsize);

  L4Re::chksys(_ds->copy_in(offset, file, 0, fsize), "copy in");
  if (sz)
    *sz = fsize;

  return L4virtio::Ptr<void>(addr.get() + fsize);
}

} // namespace
