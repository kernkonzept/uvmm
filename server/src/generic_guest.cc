/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/cache.h>
#include <l4/sys/debugger.h>

#include "generic_guest.h"

namespace Vmm {

Generic_guest::Generic_guest(L4::Cap<L4Re::Dataspace> ram,
                             l4_addr_t vm_base, l4_addr_t boot_offset)
: _registry(&_bm),
  _ram(ram, vm_base, boot_offset),
  _task(L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Task>()))
{
  // attach RAM to VM
  _memmap[Region::ss(_ram.vm_start(), _ram.size())]
    = Vdev::make_device<Ds_handler>(_ram.ram(), _ram.local_start());

  // create the VM task
  auto *e = L4Re::Env::env();
  L4Re::chksys(e->factory()->create(_task.get(), L4_PROTO_VM),
               "allocate vm");
  l4_debugger_set_object_name(_task.get().cap(), "vm-task");

  _vbus_event.register_obj(registry());
}

L4virtio::Ptr<void>
Generic_guest::load_ramdisk_at(char const *ram_disk, L4virtio::Ptr<void> addr,
                               l4_size_t *size)
{
  l4_size_t tmp;
  auto end = _ram.load_file(ram_disk, addr, &tmp);

  if (size)
    *size = tmp;

  end = l4_round_size(end, L4_PAGESHIFT);

  info().printf("Loaded ramdisk image %s to [%llx:%llx] (%08zx)\n", ram_disk,
                addr.get(), end.get() - 1, tmp);

  return end;
}

static void
throw_error(char const *msg,
            cxx::Ref_ptr<Vmm::Mmio_device> &dev, Region const &region,
            cxx::Ref_ptr<Vmm::Mmio_device> &new_dev, Region const &new_region)
{
  char buf[80], buf_new[80];
  Err().printf("%s: [%lx:%lx] (%s) <-> [%lx:%lx] (%s)\n", msg,
               region.start, region.end, dev->dev_info(buf, sizeof(buf)),
               new_region.start, new_region.end,
               new_dev->dev_info(buf_new, sizeof(buf_new)));
  L4Re::chksys(-L4_EINVAL, msg);
}

void
Generic_guest::add_mmio_device(Region const &region,
                               cxx::Ref_ptr<Vmm::Mmio_device> &&dev)
{
  if (_memmap.count(region) == 0)
    {
      _memmap[region] = dev;
      return;
    }

  auto lower = _memmap.lower_bound(region);
  auto const &current_region = lower->first;
  if (current_region.contains(region))
    {
      // Region is a subset of an already existing one, there can be
      // at most one such region
      if (!lower->second->mergable(dev, region.start, current_region.start))
        throw_error("Unmergable mmio regions",
                    lower->second, current_region, dev, region);
      return;
    }

  auto upper = _memmap.upper_bound(region);
  for(auto it = lower; it != upper; ++it)
    {
      auto const &tmp_region = it->first;
      // We already handled smaller regions above, so the region is
      // either a superset or not a candidate for a merge operation
      if (region.contains(tmp_region))
        {
          if (!it->second->mergable(dev, region.start, tmp_region.start))
            throw_error("Unmergable mmio regions",
                        lower->second, tmp_region, dev, region);
        }
      else
        throw_error("Unmergable mmio regions",
                    lower->second, tmp_region, dev, region);
    }

  // [lower, upper) is a subset of region - erase it
  _memmap.erase(lower, upper);
  _memmap[region] = dev;
}

void
Generic_guest::register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> &&dev,
                                    Vdev::Dt_node const &node, size_t index)
{
  l4_uint64_t base, size;
  int res = node.get_reg_val(index, &base, &size);
  if (res < 0)
    {
      Err().printf("Failed to read 'reg' from node %s: %s\n",
                   node.get_name(), node.strerror(res));
      throw L4::Runtime_error(-L4_EINVAL);
    }

  auto region = Region::ss(base, size);

  add_mmio_device(region, cxx::move(dev));

  info().printf("New mmio mapping: @ %llx %llx\n", base, size);
}
} // namespace
