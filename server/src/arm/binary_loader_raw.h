/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#pragma once

namespace Boot {

static int raw_load_image(std::shared_ptr<Binary_ds> image, Vmm::Vm_ram *ram,
                          Vmm::Ram_free_list *free_list,
                          l4_addr_t *entry)
{
  if (*entry == ~0ul)
    *entry = 0x208000;

  // Get the RAM start address.
  Vmm::Guest_addr ram_base = free_list->first_free_address();
  *entry = image->load_as_raw(ram, ram_base + *entry, free_list);

  return L4_EOK;
}

}
