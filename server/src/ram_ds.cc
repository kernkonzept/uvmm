/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cassert>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/l4re_vfs/backend>

#include "debug.h"
#include "generic_guest.h"
#include "ram_ds.h"

namespace Vmm {

Ram_ds::Ram_ds(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base,
               l4_addr_t boot_offset)
: _ram(ram),
  _dma(L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4Re::Dma_space>())),
  _boot_offset(boot_offset)
{
  Dbg info(Dbg::Info);

  _vm_start = vm_base;
  _size = ram->size();

  auto *env = L4Re::Env::env();

  int err = l4_error(env->user_factory()->create(_dma.get()));

  if (err >= 0)
    err = _dma->associate(L4::Ipc::Cap<L4::Task>(L4::Cap<void>::Invalid),
                          L4Re::Dma_space::Phys_space);

  if (err < 0)
    _dma = L4::Cap<L4Re::Dma_space>::Invalid;

  l4_size_t phys_size = _size;
  L4Re::Dma_space::Dma_addr phys_ram = 0;

  if (err >= 0)
    err = _dma->map(L4::Ipc::make_cap(ram, L4_CAP_FPAGE_RW),
                    0, &phys_size,
                    L4Re::Dma_space::Attributes::None,
                    L4Re::Dma_space::Bidirectional, &phys_ram);
  else
    phys_size = 0;

  if (err < 0 || phys_size < _size)
    {
      info.printf("RAM dataspace not contiguous, should not use DMA w/o IOMMU\n");
      if (err >= 0 && _vm_start == Ram_base_identity_mapped)
        {
          _vm_start = phys_ram;
          _ident = true;
        }
    }
  else
    {
      _cont = true;
      if (_vm_start == Ram_base_identity_mapped)
        {
          _vm_start = phys_ram;
          _ident = true;
        }
    }

  info.printf("RAM: @ %lx size=%x (%c%c)\n",
              _vm_start, (unsigned) _size, _cont ? 'c' : '-', _ident ? 'i' : '-');

  _local_start = 0;
  L4Re::chksys(env->rm()->attach(&_local_start, _size,
                                 L4Re::Rm::Search_addr | L4Re::Rm::Eager_map,
                                 L4::Ipc::make_cap_rw(ram), 0,
                                 L4_SUPERPAGESHIFT));
  _local_end = _local_start + _size;
  info.printf("RAM: VMM mapping @ %lx size=%x\n", _local_start, (unsigned)_size);

  assert(_vm_start != ~0UL);
  _offset = _local_start - _vm_start;
  info.printf("RAM: VM offset=%lx\n", _offset);

  _phys_ram = phys_ram;
  _phys_size = phys_size;
}


L4virtio::Ptr<void>
Ram_ds::load_file(char const *name, l4_addr_t offset, l4_size_t *_size)
{
  Dbg info(Dbg::Info, "file");

  info.printf("load: %s -> %lx\n", name, offset);
  int fd = open(name, O_RDONLY);
  if (fd < 0)
    {
      Err().printf("could not open file: %s:", name);
      L4Re::chksys(-L4_EINVAL);
    }

  cxx::Ref_ptr<L4Re::Vfs::File> file = L4Re::Vfs::vfs_ops->get_file(fd);
  if (!file)
    {
      Err().printf("bad file descriptor: %s\n", name);
      errno = EBADF;
      L4Re::chksys(-L4_EINVAL);
    }

  L4::Cap<L4Re::Dataspace> f = file->data_space();
  if (!f)
    {
      Err().printf("could not get data space for %s\n", name);
      errno = EINVAL;
      L4Re::chksys(-L4_EINVAL);
    }

  l4_size_t fsize = f->size();

  if (offset >= size() || offset + fsize >= size())
    {
      Err().printf("File does not fit into ram: %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  info.printf("copy in: %s -> %lx-%lx\n", name, offset, offset + fsize);

  L4Re::chksys(_ram->copy_in(offset, f, 0, fsize), "copy in");
  close(fd);
  if (_size)
    *_size = fsize;

  return L4virtio::Ptr<void>(offset + vm_start());
}


} // namespace
