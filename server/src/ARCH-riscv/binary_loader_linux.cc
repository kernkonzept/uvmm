/*
 * Copyright (C) 2022-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "binary_loader_linux.h"

namespace Boot {

int Linux_loader::load(char const * /*bin*/, std::shared_ptr<Binary_ds> image,
                       Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
                       l4_addr_t *entry)
{
  trace().printf("Checking for Linux image...\n");

  if (!image->is_valid())
    return -L4_EINVAL;

  Vmm::Guest_addr ram_base = free_list->first_free_address();
  unsigned char const *h = static_cast<unsigned char const *>(image->get_header());

  if (   h[0x38] == 'R' && h[0x39] == 'S'
      && h[0x3A] == 'C' && h[0x3B] == 0x05) // Linux header RSC\x05
  {
    l4_uint64_t l = *reinterpret_cast<l4_uint64_t const *>(&h[8]);
    *entry = image->load_as_raw(ram, ram_base + l, free_list);
    // TODO: Can we detect the bitness of the Linux image? Currently the _64bit
    //       field is not used by uvmm on RISC-V, but still.
    _64bit = true;
  }
  else
    return -L4_EINVAL;

  info().printf("Linux kernel detected\n");

  return L4_EOK;
}

static Linux_loader f __attribute__((init_priority(Boot::Linux)));

}
