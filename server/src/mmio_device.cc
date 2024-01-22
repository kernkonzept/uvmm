/*
 * Copyright (C) 2018, 2021-2022 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "mmio_device.h"
#include "debug.h"

namespace {

class Batch_unmapper
{
  enum { Batch_size = L4_UTCB_GENERIC_DATA_SIZE - 2 };

  L4::Cap<L4::Vm> _task;
  l4_fpage_t _fpages[Batch_size];
  unsigned _num = 0;
  l4_umword_t _mask;

  void flush()
  {
    if (_num > 0)
      L4Re::chksys(_task->unmap_batch(_fpages, _num, _mask),
                   "unmap_batch failed");
    _num = 0;
  }

public:
  explicit Batch_unmapper(L4::Cap<L4::Vm> task, l4_umword_t mask)
  : _task(task), _mask(mask)
  {}

  ~Batch_unmapper()
  { flush(); }

  void unmap(l4_fpage_t fpage)
  {
    if (_num >= Batch_size)
      flush();

    _fpages[_num++] = fpage;
  }
};

}

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
                                       l4_fpage(src + offs, ps, attr), doffs));
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

  Dbg(Dbg::Mmio, Dbg::Info, "mmio")
    .printf("\tUnmapping [%lx - %lx]\n", dest.get(), dest_end);

  Batch_unmapper b(vm_task, L4_FP_ALL_SPACES);
  while (offs < size)
    {
      auto doffs = dest.get() + offs;
      char ps = get_page_shift(doffs, dest.get(), dest_end, offs);
      b.unmap(l4_fpage(doffs, ps, L4_FPAGE_RWX));
      offs += static_cast<l4_addr_t>(1) << ps;
    }
}
