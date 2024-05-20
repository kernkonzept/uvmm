/*
 * Copyright (C) 2023-2024 genua GmbH, 85551 Kirchheim, Germany
 * All rights reserved. Alle Rechte vorbehalten.
 */
/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "binary_loader_openbsd.h"
#include "guest.h"

namespace Boot {

bool OpenBSD_loader::is_openbsd(std::shared_ptr<Binary_ds> image) const
{
  bool res = false;
  image->get_elf()->iterate_phdr([&res](Ldr::Elf_phdr ph)
    {
      if (ph.type() == Pt_openbsd_randomize)
        res = true;
    });
  return res;
}

int OpenBSD_loader::load(char const * /*bin*/, std::shared_ptr<Binary_ds> image,
                         Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
                         l4_addr_t *entry)
{
  trace().printf("Checking for OpenBSD image...\n");

  if (!image->is_valid())
    return -L4_EINVAL;

  if (!image->is_elf_binary() || !image->is_elf64() || !is_openbsd(image))
    return -L4_EINVAL;

  *entry = image->load_as_elf(ram, free_list);
  _binsize = image->loaded_size();
  info().printf("Loaded OpenBSD kernel image to 0x%lx, size 0x%zx\n", *entry,
                _binsize);

  return L4_EOK;
}

static OpenBSD_loader f __attribute__((init_priority(Boot::OpenBSD)));

}
