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
  l4_addr_t start = *entry == ~0ul ? 0x100000 : *entry;

  image->load_as_raw(ram, Vmm::Guest_addr(start), free_list);
  *entry = ram->guest_phys2boot(Vmm::Guest_addr(0x100400));

  return L4_EOK;
}

}
