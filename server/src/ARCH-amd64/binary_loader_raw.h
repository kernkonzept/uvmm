/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#pragma once

namespace Boot {

static int raw_load_image(std::shared_ptr<Binary_ds> image, Vmm::Vm_ram *ram,
                          Vmm::Ram_free_list *free_list, l4_addr_t *entry)
{
  l4_addr_t start = *entry == ~0ul ? 0x0 : *entry;

  // Get the RAM start address.
  Vmm::Guest_addr ram_base = free_list->first_free_address();
  *entry = image->load_as_raw(ram, ram_base + start, free_list);

  return L4_EOK;
}

}
