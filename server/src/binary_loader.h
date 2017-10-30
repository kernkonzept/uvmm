/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/cache.h>
#include <l4/re/dataspace>
#include <l4/re/util/unique_cap>
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
    _loaded_range_vmm.start = 0;
    _loaded_range_vmm.end = 0;
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

  bool is_elf64()
  {
    return as_elf_header()->is_64();
  }

  l4_addr_t load_as_elf(Vmm::Ram_ds *ram)
  {
    auto const *eh = as_elf_header();

    l4_addr_t img_start = (l4_addr_t)(-1L);
    l4_addr_t img_end = 0;

    eh->iterate_phdr([this,ram,&img_start,&img_end](Ldr::Elf_phdr ph) {
      if (ph.type() == PT_LOAD)
        {
          l4_addr_t dest = ram->boot2ram(ph.paddr());
          if (dest > ram->size() || dest + ph.memsz() > ram->size())
            L4Re::chksys(-L4_ERANGE, "Binary outside VM RAM region");

          l4_addr_t gupper = ph.paddr() + ph.memsz();
          if (gupper > img_end)
            img_end = gupper;

          if (ph.paddr() < img_start)
            img_start = ph.paddr();

          Dbg(Dbg::Mmio, Dbg::Info, "bin")
            .printf("Copy in ELF binary section @0x%lx from 0x%lx/0x%lx\n",
                    dest, ph.offset(), ph.filesz());
          L4Re::chksys(ram->ram()->copy_in(dest, _ds.get(),
                                           ph.offset(), ph.filesz()));
        }
    });

    _loaded_range_vmm.start = (l4_addr_t)ram->access(ram->boot2guest_phys<void>(img_start));
    _end = ram->boot2guest_phys<void>(img_end);
    _loaded_range_vmm.end =   (l4_addr_t)ram->access(_end);
    return eh->entry();
  }

  l4_addr_t load_as_raw(Vmm::Ram_ds *ram, l4_addr_t ram_offset)
  {
    L4virtio::Ptr<void> start(ram->vm_start() + ram_offset);
    _end = ram->load_file(_ds.get(), start, nullptr);
    _loaded_range_vmm.start = (l4_addr_t)ram->access(start);
    _loaded_range_vmm.end =   (l4_addr_t)ram->access(_end);
    return start.get();
  }

  void const *get_header() const
  { return _header.get(); }

  L4virtio::Ptr<void> get_upper_bound()
  { return _end; }

  ~Binary_ds()
  {
    if (_loaded_range_vmm.start !=0 && _loaded_range_vmm.end != 0)
      l4_cache_coherent(_loaded_range_vmm.start,
                        _loaded_range_vmm.end);
  }

private:
  Ldr::Elf_ehdr const *as_elf_header() const
  { return reinterpret_cast<Ldr::Elf_ehdr const*>(_header.get()); }

  L4Re::Util::Unique_cap<L4Re::Dataspace> _ds;
  L4Re::Rm::Unique_region<char *> _header;
  L4virtio::Ptr<void> _end;
  struct Region
  {
    l4_addr_t start, end;
  };

  Region _loaded_range_vmm;
};

} // namespace
