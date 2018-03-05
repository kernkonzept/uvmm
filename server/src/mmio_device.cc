/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "mmio_device.h"
#include "debug.h"

void Vmm::Mmio_device::map_guest_range(L4::Cap<L4::Task> vm_task,
                                       l4_addr_t dest, l4_addr_t src,
                                       l4_size_t size, unsigned attr)
{
  l4_addr_t dest_end = dest + size;
  l4_addr_t src_end = src + size;
  l4_addr_t offs = 0;

  Dbg(Dbg::Mmio, Dbg::Info, "mmio")
    .printf("\tMapping [%lx - %lx] -> [%lx - %lx]\n", src, src_end, dest,
            dest_end);

  while (src + offs < src_end)
    {
      char ps = get_page_shift(dest + offs, dest, dest_end, offs, src);
      auto res = l4_error(vm_task->map(L4Re::This_task,
                                       l4_fpage(src + offs, ps, attr),
                                       dest + offs));
      if (res < 0)
        Err().printf("Could not map (%lx, %c) to (%lx, %c)\n", src + offs, ps,
                     dest + offs, ps);
      offs += 1 << ps;
    }
}
