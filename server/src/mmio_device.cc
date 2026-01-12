/*
 * Copyright (C) 2018, 2021-2024 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "mmio_device.h"
#include "batch_unmapper.h"
#include "debug.h"
#include "consts.h"

#include <l4/util/printf_helpers.h>

void Vmm::Mmio_device::map_guest_range(L4::Cap<L4::Vm> vm_task,
                                       Vmm::Guest_addr dest, l4_addr_t src,
                                       l4_size_t size, unsigned attr)
{
  l4_addr_t dest_end = dest.get() + size - 1;
  l4_addr_t offs = 0;

  Dbg d(Dbg::Mmio, Dbg::Info, "mmio");
  if (d.is_active())
    {
      char sz[64];
      l4util_human_readable_size(sz, sizeof(sz), size);
      d.printf("  Mapping [%08lx-%08lx] -> [%08lx-%08lx] (%10s) %s\n",
               src, src + size - 1, dest.get(), dest_end, sz, dev_name());
    }

  while (offs < size)
    {
      auto doffs = dest.get() + offs;
      char ps = Vmm::get_page_shift(doffs, dest.get(), dest_end, offs, src);
      // Map explicitly cacheable into VM task. This lets the guest choose the
      // effective memory attributes.
      auto res = l4_error(vm_task->map(L4Re::This_task,
                                       l4_fpage(src + offs, ps, attr),
                                       l4_map_control(doffs,
                                                      L4_FPAGE_CACHEABLE,
                                                      L4_MAP_ITEM_MAP)));
      if (res < 0)
        {
          Err().printf("Could not map (%lx, %d) to (%lx, %d)\n",
                       src + offs, ps, doffs, ps);
          L4Re::throw_error(-L4_ENOMEM, "Mapping guest range.");
        }

      offs += static_cast<l4_addr_t>(1) << ps;
    }
}

void Vmm::Mmio_device::unmap_guest_range(L4::Cap<L4::Vm> vm_task,
                                         Vmm::Guest_addr dest, l4_size_t size)
{
  l4_addr_t dest_end = dest.get() + size - 1;
  l4_addr_t offs = 0;

  Dbg d(Dbg::Mmio, Dbg::Info, "mmio");
  if (d.is_active())
    {
      char sz[64];
      l4util_human_readable_size(sz, sizeof(sz), size);
      d.printf("  Unmapping [%08lx-%08lx] (%9s) %s\n",
               dest.get(), dest_end, sz, dev_name());
    }

  Vmm::Batch_unmapper b(vm_task, L4_FP_ALL_SPACES);
  while (offs < size)
    {
      auto doffs = dest.get() + offs;
      char ps = Vmm::get_page_shift(doffs, dest.get(), dest_end, offs);
      b.unmap(l4_fpage(doffs, ps, L4_FPAGE_RWX));
      offs += static_cast<l4_addr_t>(1) << ps;
    }
}
