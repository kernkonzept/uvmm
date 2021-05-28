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
#include <l4/re/util/env_ns>
#include <l4/re/util/unique_cap>

#include "debug.h"
#include "host_dt.h"

static Dbg warn(Dbg::Core, Dbg::Warn, "main");

namespace {

  class Mapped_file
  {
  public:
    explicit Mapped_file(char const *name)
    {
      L4Re::Util::Env_ns ens;
      L4Re::Util::Unique_cap<L4Re::Dataspace> f(ens.query<L4Re::Dataspace>(name));
      if (!f)
        {
          warn.printf("Unable to open file '%s'\n", name);
          return;
        }

      _size = l4_round_page(f->size());

      auto env = L4Re::Env::env();
      _ds = L4Re::Util::make_unique_cap<L4Re::Dataspace>();
      L4Re::chksys(env->mem_alloc()->alloc(_size, _ds.get()));
      L4Re::chksys(_ds->copy_in(0, f.get(), 0, _size));

      int err = env->rm()->attach(&_addr, _size,
                                  L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW,
                                  _ds.get(),
                                  0);
      if (err < 0)
        {
          warn.printf("Unable to mmap file '%s'(%zu): %s\n", name, _size, strerror(-err));
          return;
        }
    }
    Mapped_file(Mapped_file &&) = delete;
    Mapped_file(Mapped_file const &) = delete;

    ~Mapped_file()
    {
      if (_addr)
        {
          L4::Cap<L4Re::Rm> r = L4Re::Env::env()->rm();

          int err = r->detach(l4_addr_t(_addr), 0);
          if (err < 0)
            warn.printf("Unable to unmap file at addr %p: %s\n",
                        _addr, strerror(-err));
        }
    }

    void *get() const { return _addr; }
    bool valid() { return _addr != 0; }

  private:
    L4Re::Util::Unique_cap<L4Re::Dataspace> _ds;
    size_t _size = 0;
    void *_addr = 0;
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
