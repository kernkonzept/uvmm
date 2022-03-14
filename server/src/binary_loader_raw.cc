/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include "binary_loader.h"
#include "binary_loader_raw.h"

namespace Boot {

class Raw_loader : public Binary_loader
{
public:
  Raw_loader()
  : Binary_loader(Raw)
  {}

  int load(char const *bin, std::shared_ptr<Binary_ds> image, Vmm::Vm_ram *ram,
           Vmm::Ram_free_list *free_list, l4_addr_t *entry) override
  {
    trace().printf("Checking for raw image...\n");

    if (!image->is_valid())
      return -EINVAL;

    *entry = ~0ul;

    if (strstr(bin, "raw:"))
      {
        char const *e = strstr(bin, "addr=");
        if (e)
          *entry = strtol(e + 5, NULL, 16);
      }

    return raw_load_image(image, ram, free_list, entry);
  }
};

// The raw loader should always be last
static Raw_loader f __attribute__((init_priority(Boot::Raw)));

}
