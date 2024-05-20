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

#pragma once

#include "binary_loader.h"

namespace Boot {

class OpenBSD_loader : public Binary_loader
{
  enum { Pt_openbsd_randomize = 0x65a3dbe6 };

public:
  OpenBSD_loader()
  : Binary_loader(OpenBSD)
  {}

  bool is_openbsd(std::shared_ptr<Binary_ds> image) const;
  int load(char const *bin, std::shared_ptr<Binary_ds> image, Vmm::Vm_ram *ram,
           Vmm::Ram_free_list *free_list, l4_addr_t *entry) override;
};

}
