/*
 * Copyright (C) 2022, 2024 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
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
