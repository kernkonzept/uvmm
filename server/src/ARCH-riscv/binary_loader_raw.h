/*
 * Copyright (C) 2022-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

namespace Boot {

enum
{
#if __riscv_xlen == 32
  Kernel_boot_address = 0x80400000,
#else
  Kernel_boot_address = 0x80200000,
#endif
};

static int raw_load_image(std::shared_ptr<Binary_ds> image, Vmm::Vm_ram *ram,
                          Vmm::Ram_free_list *free_list, l4_addr_t *entry)
{
  *entry = image->load_as_raw(ram, Vmm::Guest_addr(Kernel_boot_address),
                              free_list);
  return L4_EOK;
}

}
