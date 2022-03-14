/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include "binary_loader.h"

namespace Boot {

class Pe_loader : public Binary_loader
{
public:
  Pe_loader()
  : Binary_loader(Pe)
  {}

  int load(char const * /*bin*/, std::shared_ptr<Binary_ds> image, Vmm::Vm_ram * /*ram*/,
           Vmm::Ram_free_list * /*free_list*/, l4_addr_t * /*entry*/) override
  {
    trace().printf("Checking for pe image...\n");

    if (!image->is_valid())
      return -EINVAL;

    unsigned char const *h = static_cast<unsigned char const *>(image->get_header());

    if (h[0] == 0x4d && h[1] == 0x5a /* "MZ */)
      {
        l4_uint32_t o = *reinterpret_cast<l4_int32_t const *>(&h[0x3c]);
        if (o <= L4_PAGESIZE - 4
            && h[o+0] == 0x50 && h[o+1] == 0x45
            && h[o+2] == 0x00 && h[o+3] == 0x00 /* "PE\0\0" */)
          L4Re::throw_error(-L4_EINVAL,
                            "Cannot boot EFI images! Was the ARM header stripped?");
        else
          L4Re::throw_error(-L4_EINVAL,
                            "Cannot boot images with 'MZ' header.");
      }

    return -EINVAL;
  }
};

// The raw loader should always be last
static Pe_loader f __attribute__((init_priority(Boot::Pe)));

}
