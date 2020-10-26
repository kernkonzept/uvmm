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

#include "debug.h"
#include "host_dt.h"

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
          warn.printf("Unable to open file '%s': %s\n", name, strerror(errno));
          return;
        }

      struct stat buf;
      if (fstat(fd, &buf) < 0)
        {
          warn.printf("Unable to get size of file '%s': %s\n", name,
                       strerror(errno));
          close(fd);
          return;
        }
      _size = buf.st_size;

      _addr = mmap(nullptr, _size, PROT_WRITE | PROT_READ, MAP_PRIVATE, fd, 0);
      if (_addr == MAP_FAILED)
        warn.printf("Unable to mmap file '%s': %s\n", name, strerror(errno));

      close(fd);
    }
    Mapped_file(Mapped_file &&) = delete;
    Mapped_file(Mapped_file const &) = delete;

    ~Mapped_file()
    {
      if (_addr != MAP_FAILED)
        {
          if (munmap(_addr, _size) < 0)
            warn.printf("Unable to unmap file at addr %p: %s\n",
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

  Dtb::Fdt fdt(mem.get());
  Device_tree dt(&fdt);

  dt.check_tree();

  // XXX would be nice to expand dynamically
  _fdt = new Dtb::Fdt(fdt, cxx::max(dt.size(), 0x200U));
}

void
Vdev::Host_dt::set_command_line(char const *cmd_line)
{
  if (!valid() || !cmd_line)
    return;

  // assume /choosen is present at this point
  auto node = get().path_offset("/chosen");
  node.setprop_string("bootargs", cmd_line);
}
