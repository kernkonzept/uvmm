/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/l4re_vfs/backend>

#include "vm_ram.h"
#include "vm_memmap.h"

namespace {

class Auto_fd
{
public:
  explicit Auto_fd(int fd) : _fd(fd) {}
  Auto_fd(Auto_fd &&) = delete;
  Auto_fd(Auto_fd const &) = delete;

  ~Auto_fd()
  {
    if (_fd >= 0)
      close(_fd);
  }

  int get() const { return _fd; }

private:
  int _fd;
};

}

Vmm::Vm_ram::Vm_ram(l4_addr_t vm_base, l4_addr_t boot_offset, Vm_mem *vmm)
: _boot_offset(boot_offset)
{
  auto ds = L4Re::chkcap(L4Re::Env::env()->get_cap<L4Re::Dataspace>("ram"),
                         "Look up 'ram' capability.", -L4_ENOENT);

  add_memory_region(ds, vm_base, vmm);
}


void
Vmm::Vm_ram::add_memory_region(L4::Cap<L4Re::Dataspace> ds, l4_addr_t baseaddr,
                               Vm_mem *vmm)
{
  _regions.emplace_back(ds, baseaddr);

  auto const &r = _regions.back();

  auto dsdev = Vdev::make_device<Ds_handler>(ds, r.local_start(), r.size());
  vmm->add_mmio_device(Region::ss(r.vm_start(), r.size()), std::move(dsdev));
}


L4virtio::Ptr<void>
Vmm::Vm_ram::load_file(char const *name, L4virtio::Ptr<void> addr, l4_size_t *sz) const
{
  Dbg info(Dbg::Mmio, Dbg::Info, "file");

  info.printf("load: %s -> 0x%llx\n", name, addr.get());
  Auto_fd fd(open(name, O_RDONLY));
  if (fd.get() < 0)
    {
      Err().printf("could not open file: %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  cxx::Ref_ptr<L4Re::Vfs::File> file = L4Re::Vfs::vfs_ops->get_file(fd.get());
  if (!file)
    {
      Err().printf("bad file descriptor: %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  L4::Cap<L4Re::Dataspace> f = file->data_space();
  if (!f)
    {
      Err().printf("could not get data space for %s\n", name);
      L4Re::chksys(-L4_EINVAL);
    }

  return load_file(f, addr, sz);
}
