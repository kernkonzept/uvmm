/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include "binary_loader_linux.h"
#include "guest_subarch.h"

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

  if (Vmm::Guest_64bit_supported
      && h[0x38] == 0x41 && h[0x39] == 0x52
      && h[0x3A] == 0x4d && h[0x3B] == 0x64) // Linux header ARM\x64
  {
    l4_uint64_t l = *reinterpret_cast<l4_uint64_t const *>(&h[8]);
    *entry = image->load_as_raw(ram, ram_base + l, free_list);
    _64bit = true;
  }
  else if (   h[0x24] == 0x18 && h[0x25] == 0x28
           && h[0x26] == 0x6f && h[0x27] == 0x01) // Linux magic
  {
    l4_uint32_t l = *reinterpret_cast<l4_uint32_t const *>(&h[0x28]);
    // Bytes 0x2c-0x2f have the zImage size
    *entry = image->load_as_raw(ram, ram_base + l, free_list);
  }
  else if (h[0] == 0x1f && h[1] == 0x8b && h[2] == 0x08)
    {
    // Gzip compressed kernel images are not self-decompressing on ARM
    L4Re::throw_error(-L4_EINVAL,
      "Cannot boot compressed images! Unzip first or enable uvmm gzip support.");
    }
  else
    return -L4_EINVAL;

  info().printf("Linux kernel detected\n");

  return L4_EOK;
}

static Linux_loader f __attribute__((init_priority(Boot::Linux)));

}
