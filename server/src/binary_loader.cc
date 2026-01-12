/*
 * Copyright (C) 2022, 2024-2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "binary_loader.h"

namespace Boot {

l4_addr_t
Binary_ds::load_as_elf(Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list)
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

l4_addr_t
Binary_ds::load_as_raw(Vmm::Vm_ram *ram, Vmm::Guest_addr start,
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

int
Binary_loader_factory::load(char const *bin, Vmm::Vm_ram *ram,
                            Vmm::Ram_free_list *free_list,
                            l4_addr_t *entry)
{
  // Reverse search for the last ':'
  char const *file = bin;
  if (char const *t = strrchr(file, ':'))
    file = t + 1;

  std::shared_ptr<Boot::Binary_ds> image = std::make_shared<Boot::Binary_ds>(file);
  int res = -L4_EINVAL;
  for (auto *t: Binary_loader::types)
    {
      res = t->load(bin, image, ram, free_list, entry);
      if (res == L4_EOK)
        {
          _loader = t;
          break;
        }
    }

  if (res != L4_EOK)
    {
      // If we didn't find a loader, check if the image is valid at all.
      // Check this late to avoid a special check for rom:/raw: arguments.
      if (!image->is_valid())
        {
          Err().printf("File not found: filename: '%s' / cmdline arg: '%s'\n",
                       file, bin);
          L4Re::throw_error(-L4_ENOENT,
                            "Binary file / Kernel image not found.");
        }
      else
        L4Re::throw_error(res, "No loader found for provided image.");
    }

  return res;
}

cxx::H_list_t<Binary_loader> Binary_loader::types(true);

}
