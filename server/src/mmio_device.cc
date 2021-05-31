/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "mmio_device.h"
#include "debug.h"

void Vmm::Mmio_device::map_guest_range(L4::Cap<L4::Vm> vm_task,
                                       Vmm::Guest_addr dest, l4_addr_t src,
                                       l4_size_t size, unsigned attr)
{
  l4_addr_t dest_end = dest.get() + size - 1;
  l4_addr_t offs = 0;

  Dbg(Dbg::Mmio, Dbg::Info, "mmio")
    .printf("\tMapping [%lx - %lx] -> [%lx - %lx]\n", src, src + size - 1,
            dest.get(), dest_end);

  while (offs < size)
    {
      auto doffs = dest.get() + offs;
      char ps = get_page_shift(doffs, dest.get(), dest_end, offs, src);
      auto res = l4_error(vm_task->map(L4Re::This_task,
                                       l4_fpage(src + offs, ps, attr),
                                       doffs));
      if (res < 0)
        Err().printf("Could not map (%lx, %d) to (%lx, %d)\n", src + offs, ps,
                     doffs, ps);
      offs += 1 << ps;
    }
}
