/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#pragma once

#include "binary_loader.h"

namespace Boot {

class Linux_loader : public Binary_loader
{
public:
  Linux_loader()
  : Binary_loader(Linux)
  {}

  int load(char const *bin, std::shared_ptr<Binary_ds> image, Vmm::Vm_ram *ram,
           Vmm::Ram_free_list *free_list, l4_addr_t *entry) override;
};

}
