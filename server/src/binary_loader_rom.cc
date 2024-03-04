/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include "binary_loader.h"

namespace Boot {

/**
 * Binary loader which starts binary out of a guest memory location.
 *
 * Use rom:addr=0xXXXXXX as uvmm's --kernel parameter.
 */
class Rom_loader : public Binary_loader
{
public:
  Rom_loader()
  : Binary_loader(Rom)
  {}

  int load(char const *bin, std::shared_ptr<Binary_ds> /*image*/,
           Vmm::Vm_ram * /*ram*/, Vmm::Ram_free_list * /*free_list*/,
           l4_addr_t *entry) override
  {
    trace().printf("Checking for rom start...\n");

    if (!strstr(bin, "rom:"))
      return -L4_EINVAL;

    char const *e = strstr(bin, "addr=");
    if (!e)
      {
        warn().printf("Start address for rom missing.");
        return -L4_EINVAL;
      }

    *entry = strtol(e + 5, NULL, 0);

    e = strstr(bin, "64bit");
    if (e)
      _64bit = true;

    info().printf("Rom start detected\n");
    warn().printf("Rom start address: 0x%lx mode: %sbit\n", *entry,
                  _64bit ? "64" : "32");

    return L4_EOK;
  }
};

static Rom_loader f __attribute__((init_priority(Boot::Rom)));

}
