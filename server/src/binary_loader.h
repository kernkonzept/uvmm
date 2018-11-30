/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/dataspace>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/env_ns>
#include <l4/re/error_helper>
#include <l4/libloader/elf>

#include "debug.h"
#include "ram_ds.h"

namespace Boot {

class Binary_ds
{
public:
  Binary_ds(char const *name)
  : _ds(L4Re::chkcap(L4Re::Util::Env_ns().query<L4Re::Dataspace>(name),
                     "Kernel binary not found", -L4_EIO))
  {
    // Map the first page which should contain all headers necessary
    // to interpret the binary.
    auto *e = L4Re::Env::env();
    L4Re::chksys(e->rm()->attach(&_header, L4_PAGESIZE, L4Re::Rm::Search_addr,
                                 L4::Ipc::make_cap_rw(_ds.get())));
  }


  bool is_elf_binary()
  {
    return as_elf_header()->is_valid();
  }


  l4_addr_t load_as_elf(Vmm::Ram_ds *ram)
  {
    auto const *eh = as_elf_header();

    eh->iterate_phdr([this,ram](Ldr::Elf_phdr ph) {
      if (ph.type() == PT_LOAD)
        {
          l4_addr_t dest = ram->boot2ram(ph.paddr());
          if (dest > ram->size() || dest + ph.memsz() > ram->size())
            L4Re::chksys(-L4_ERANGE, "Binary outside VM RAM region");
          Dbg().printf("Copy in ELF binary section @0x%lx from 0x%lx/0x%lx\n",
                       dest, ph.offset(), ph.filesz());
          L4Re::chksys(ram->ram()->copy_in(dest, _ds.get(),
                                           ph.offset(), ph.filesz()));
        }
    });

    return eh->entry();
  }


  void elf_addr_bounds(l4_addr_t *lower, l4_addr_t *upper) const
  {
    *lower = -1UL;
    *upper = 0;

    auto const *eh = as_elf_header();
    unsigned n = eh->num_phdrs();

    for (unsigned i = 0; i < n; ++i)
      {
        auto ph = eh->phdr(i);
        if (ph.type() == PT_LOAD)
          {
            l4_addr_t u = ph.paddr() + ph.memsz();
            if (u > *upper)
              *upper = u;

            if (ph.paddr() < *lower)
              *lower = ph.paddr();
          }
      }
  }

private:
  Ldr::Elf_ehdr const *as_elf_header() const
  { return reinterpret_cast<Ldr::Elf_ehdr const*>(_header.get()); }

  L4Re::Util::Auto_cap<L4Re::Dataspace>::Cap _ds;
  L4Re::Rm::Auto_region<char *> _header;
};

} // namespace
