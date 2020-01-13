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
#include "vm_ram.h"

namespace Boot {

class Binary_ds
{
public:
  Binary_ds(char const *name)
  : _ds(L4Re::chkcap(L4Re::Util::Env_ns().query<L4Re::Dataspace>(name),
                     "Kernel binary not found", -L4_EIO)),
    _elf(this, _ds.get())
  {
    _loaded_range_start = 0;
    _loaded_range_end = 0;

    // return if we found an ELF binary, otherwise
    // attach first page
    if (_elf.is_valid())
      return;

    // Map the first page which should contain all headers necessary
    // to interpret the binary.
    auto *e = L4Re::Env::env();
    L4Re::chksys(e->rm()->attach(&_header, L4_PAGESIZE,
                                 L4Re::Rm::F::Search_addr | L4Re::Rm::F::RWX,
                                 L4::Ipc::make_cap_rw(_ds.get())));
  }


  bool is_elf_binary()
  {
    return _elf.is_valid();
  }

  bool is_elf64()
  {
    return _elf.is_64();
  }

  l4_addr_t load_as_elf(Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list)
  {
    Vmm::Guest_addr img_start(-1UL);
    Vmm::Guest_addr img_end(0);

    _elf.iterate_phdr([this,ram,free_list,&img_start,&img_end](Ldr::Elf_phdr ph) {
      if (ph.type() == PT_LOAD)
        {
          auto gstart = ram->boot2guest_phys(ph.paddr());
          // Note that we need to reserve all the memory, this block will
          // occupy in memory, even though only filesz() will be copied
          // later.
          if (!free_list->reserve_fixed(gstart, ph.memsz()))
            {
              Err().printf("Failed to load ELF kernel binary. "
                           "Region [0x%lx/0x%lx] not in RAM.\n",
                           ph.paddr(), ph.filesz());
              L4Re::chksys(-L4_ENOMEM, "Loading ELF binary.");
            }

          if (img_start > gstart)
            img_start = gstart;
          if (img_end.get() < gstart.get() + ph.filesz())
            img_end = gstart + ph.filesz();

          Dbg(Dbg::Mmio, Dbg::Info, "bin")
            .printf("Copy in ELF binary section @0x%lx from 0x%lx/0x%lx\n",
                    ph.paddr(), ph.offset(), ph.filesz());

          ram->copy_from_ds(_ds.get(), ph.offset(), gstart, ph.filesz());
        }
    });

    if (img_start >= img_end)
      {
        Err().printf("ELF binary does not have any PT_LOAD sections.\n");
        L4Re::chksys(-L4_ENOMEM, "Loading ELF binary.");
      }

    _loaded_range_start = ram->guest2host<l4_addr_t>(img_start);
    _loaded_range_end = ram->guest2host<l4_addr_t>(img_end);

    return _elf.entry();
  }

  l4_addr_t load_as_raw(Vmm::Vm_ram *ram, Vmm::Guest_addr start,
                        Vmm::Ram_free_list *free_list)
  {
    l4_size_t sz = _ds->size();

    if (!free_list->reserve_fixed(start, sz))
      {
        Err().printf("Failed to load kernel binary. Region [0x%lx/0x%llx] not in RAM.\n",
                     start.get(), _ds->size());
        L4Re::chksys(-L4_ENOMEM, "Loading kernel binary.");
      }

    ram->load_file(_ds.get(), start, sz);

    _loaded_range_start = ram->guest2host<l4_addr_t>(start);
    _loaded_range_end = _loaded_range_start + sz;

    return ram->guest_phys2boot(start);
  }

  void const *get_header() const
  { return _header.get(); }

  ~Binary_ds()
  {
    if (_loaded_range_start != 0 && _loaded_range_end != 0)
      l4_cache_coherent(_loaded_range_start, _loaded_range_end);
  }

  // App_model API
  typedef L4::Cap<L4Re::Dataspace> Const_dataspace;
  l4_addr_t local_attach_ds(Const_dataspace c,
                            l4_size_t size, l4_addr_t offset) const
  {
    auto *e = L4Re::Env::env();
    l4_addr_t pg_offset = l4_trunc_page(offset);
    l4_addr_t in_pg_offset = offset - pg_offset;
    unsigned long pg_size = l4_round_page(size + in_pg_offset);
    l4_addr_t adr = 0;

    if (e->rm()->attach(&adr, pg_size,
                        L4Re::Rm::F::Search_addr | L4Re::Rm::F::R,
                        c, pg_offset) < 0)
      return 0;

    return adr + in_pg_offset;
  }

  void local_detach_ds(l4_addr_t addr, l4_size_t) const
  {
    L4::Cap<L4Re::Dataspace> c;
    L4Re::Env::env()->rm()->detach(addr, &c);
  }
  // end of App_model API

private:
  L4Re::Util::Unique_cap<L4Re::Dataspace> _ds;
  Ldr::Elf_binary<Binary_ds> _elf;
  L4Re::Rm::Unique_region<char *> _header;
  l4_addr_t _loaded_range_start;
  l4_addr_t _loaded_range_end;
};

} // namespace
