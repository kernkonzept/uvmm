/*
 * Copyright (C) 2015-2019, 2021-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "vm_memmap.h"


void Vmm::Vm_mem::dump(Dbg::Verbosity l) const
{
  Dbg d(Dbg::Dev, l, "vmmap");
  if (d.is_active())
    {
      d.printf("VM map:\n");
      for (auto const &r: *this)
        d.printf(" [%8lx:%8lx]: %s\n",
                 r.first.start.get(), r.first.end.get(),
                 r.second->dev_name());
    }
}

void
Vmm::Vm_mem::throw_error(char const *msg,
            cxx::Ref_ptr<Vmm::Mmio_device> const &dev, Vmm::Region const &region,
            cxx::Ref_ptr<Vmm::Mmio_device> const &new_dev, Vmm::Region const &new_region)
{
  char buf[80], buf_new[80];
  dump(Dbg::Warn);
  Err().printf("%s:\n"
               " VM addresses: [%08lx:%08lx] <-> [%08lx:%08lx]\n"
               " Device info:  %s <-> %s\n", msg,
               region.start.get(), region.end.get(),
               new_region.start.get(), new_region.end.get(),
               dev->dev_info(buf, sizeof(buf)),
               new_dev->dev_info(buf_new, sizeof(buf_new)));
  L4Re::throw_error(-L4_EINVAL, msg);
}

void
Vmm::Vm_mem::add_mmio_device(Vmm::Region const &region,
                             cxx::Ref_ptr<Vmm::Mmio_device> const &dev)
{
  if (count(region) == 0)
    {
      insert(std::make_pair(region, dev));
      return;
    }

  auto lower = lower_bound(region);
  auto const &current_region = lower->first;

  // We can't merge if the region is marked moveable
  if (region.flags & Region_flags::Moveable)
    throw_error("Unmergable mmio regions in VM address space: region is moveable",
                lower->second, current_region, dev, region);

  if (current_region.contains(region))
    {
      // Region is a subset of an already existing one, there can be
      // at most one such region
      if (!lower->second->mergable(dev, region.start, current_region.start))
        throw_error("Unmergable mmio regions in VM address space: region is subset",
                    lower->second, current_region, dev, region);
      return;
    }

  auto upper = upper_bound(region);
  for(auto it = lower; it != upper; ++it)
    {
      auto const &tmp_region = it->first;
      // We already handled smaller regions above, so the region is
      // either a superset or not a candidate for a merge operation
      if (region.contains(tmp_region))
        {
          if (!it->second->mergable(dev, region.start, tmp_region.start))
            throw_error("Unmergable mmio regions in VM address space: region is superset",
                        lower->second, tmp_region, dev, region);
        }
      else
        throw_error("Unmergable mmio regions in VM address space",
                    lower->second, tmp_region, dev, region);
    }

  // [lower, upper) is a subset of region - erase it
  erase(lower, upper);
  insert(std::make_pair(region, dev));
}
