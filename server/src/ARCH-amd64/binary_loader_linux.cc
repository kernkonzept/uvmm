/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.potzsch@kernkonzept.com>
 *
 */

#include "binary_loader_linux.h"
#include "guest.h"

namespace Boot {

enum : unsigned
{
  Linux_kernel_start_addr = 0x100000,
};

int Linux_loader::load(char const * /*bin*/, std::shared_ptr<Binary_ds> image,
                       Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list,
                       l4_addr_t *entry)
{
  trace().printf("Checking for Linux image...\n");

  if (!image->is_valid())
    return -L4_EINVAL;

  unsigned char const *h = static_cast<unsigned char const *>(image->get_header());
  if (!(h[0x1fe] == 0x55 && h[0x1ff] == 0xaa))
    return -L4_EINVAL;

  info().printf("Linux kernel detected\n");

  _64bit = true;

  l4_uint8_t num_setup_sects = *(h + Vmm::Bp_setup_sects);
  trace().printf("number of setup sections found: 0x%x\n", num_setup_sects);

  // 512 is the size of a segment
  l4_addr_t setup_sects_size = (num_setup_sects + 1) * 512;

  if (Linux_kernel_start_addr < setup_sects_size)
    L4Re::chksys(-L4_EINVAL,
                 "Supplied kernel image contains an invalid number "
                 " of setup sections (zeropage).");

  l4_addr_t start = Linux_kernel_start_addr - setup_sects_size;
  trace().printf("size of setup sections: 0x%lx\n", setup_sects_size);
  trace().printf("loading binary at: 0x%lx\n", start);

  // load the binary starting after the boot_params
  *entry = image->load_as_raw(ram, ram->boot2guest_phys(start), free_list);
  trace().printf("Loaded kernel image as raw to 0x%lx\n", *entry);
  trace().printf("load kernel as raw entry to 0x%lx\n",
                 ram->guest_phys2boot(
                   Vmm::Guest_addr(Linux_kernel_start_addr)));

  return L4_EOK;
}

static Linux_loader f __attribute__((init_priority(Boot::Linux)));

}
