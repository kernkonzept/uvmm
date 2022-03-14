/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include "binary_loader.h"

namespace Boot {

class Elf_loader : public Binary_loader
{
public:
  Elf_loader()
  : Binary_loader(Elf)
  {}

  int load(char const * /*bin*/, std::shared_ptr<Binary_ds> image,
           Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
           l4_addr_t *entry) override
  {
    trace().printf("Checking for elf image...\n");

    if (!image->is_valid() || !image->is_elf_binary())
      return -L4_EINVAL;

    info().printf("Elf image detected\n");

    _64bit = image->is_elf64();
    *entry = image->load_as_elf(ram, free_list);

    return L4_EOK;
  }
};

static Elf_loader f __attribute__((init_priority(Boot::Elf)));

}
