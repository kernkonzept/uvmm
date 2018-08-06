/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/debugger.h>

#include "generic_guest.h"

namespace Vmm {

Generic_guest::Generic_guest()
: _registry(&_bm),
  _task(L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Task>()))
{
  // create the VM task
  auto *e = L4Re::Env::env();
  L4Re::chksys(e->factory()->create(_task.get(), L4_PROTO_VM),
               "allocate vm");
  l4_debugger_set_object_name(_task.get().cap(), "vm-task");

  _vbus_event.register_obj(registry());
}

bool
Generic_guest::mmio_region_valid(l4_uint64_t addr, l4_uint64_t size)
{
    Vm_mem::const_iterator f = _memmap.find(addr);
    return (f != _memmap.end()) && (addr + size <= f->first.end + 1);

}

void
Generic_guest::register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> const &dev,
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

  add_mmio_device(region, dev);

  info().printf("New mmio mapping: @ %llx %llx\n", base, size);
}
} // namespace
