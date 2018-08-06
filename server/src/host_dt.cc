/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cerrno>

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <l4/cxx/minmax>
#include <l4/re/error_helper>
#include <l4/sys/cache.h>

#include "debug.h"
#include "host_dt.h"
#include "vm_ram.h"

static Dbg warn(Dbg::Core, Dbg::Warn, "main");

namespace {

  class Mapped_file
  {
  public:
    explicit Mapped_file(char const *name)
    {
      int fd = open(name, O_RDWR);
      if (fd < 0)
        {
          warn.printf("Unable to open file '%s': %s", name, strerror(errno));
          return;
        }

      struct stat buf;
      if (fstat(fd, &buf) < 0)
        {
          warn.printf("Unable to get size of file '%s': %s", name,
                       strerror(errno));
          close(fd);
          return;
        }
      _size = buf.st_size;

      _addr = mmap(&_addr, _size, PROT_WRITE | PROT_READ, MAP_PRIVATE, fd, 0);
      if (_addr == MAP_FAILED)
        warn.printf("Unable to mmap file '%s': %s", name, strerror(errno));

      close(fd);
    }
    Mapped_file(Mapped_file &&) = delete;
    Mapped_file(Mapped_file const &) = delete;

    ~Mapped_file()
    {
      if (_addr != MAP_FAILED)
        {
          if (munmap(_addr, _size) < 0)
            warn.printf("Unable to unmap file at addr %p: %s",
                        _addr, strerror(errno));
        }
    }

    void *get() const { return _addr; }
    bool valid() { return _addr != MAP_FAILED; }

  private:
    size_t _size = 0;
    void *_addr = MAP_FAILED;
  };

}

void
Vdev::Host_dt::add_source(char const *fname)
{
  Mapped_file mem(fname);
  if (!mem.valid())
    L4Re::chksys(-L4_EINVAL, "Unable to access overlay");

  if (valid())
    {
      get().apply_overlay(mem.get(), fname);
      return;
    }

  Device_tree dt(mem.get());

  dt.check_tree();

  // XXX would be nice to expand dynamically
  l4_size_t padding = cxx::max(dt.size(), 0x200U);

  _dtmem = malloc(dt.size() + padding);
  if (!_dtmem)
    L4Re::chksys(-L4_ENOMEM, "Allocating memory for temporary device tree.");

  memcpy(_dtmem, mem.get(), dt.size());
  get().add_to_size(padding);
}

L4virtio::Ptr<void>
Vdev::Host_dt::pack_and_move(Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list)
{
  fdt_pack(_dtmem);

  l4_size_t new_size = get().size();
  l4_addr_t addr;

  if (!free_list->reserve_back(new_size, &addr))
    L4Re::chksys(-L4_ENOMEM, "Copy device tree into guest memory.");

  void *target = ram->guest_region2host<void>(addr, new_size);

  fdt_move(_dtmem, target, new_size);

  l4_addr_t ds_start = reinterpret_cast<l4_addr_t>(target);
  l4_cache_clean_data(ds_start, ds_start + new_size);

  Dbg().printf("Cleaning caches for device tree [%lx-%lx] ([%lx])\n",
              ds_start, ds_start + new_size, addr);

  free(_dtmem);
  _dtmem = nullptr;

  return L4virtio::Ptr<void>(addr);
}
