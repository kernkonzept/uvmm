/*
 * Copyright (C) 2015-2019, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/debugger.h>

#include "generic_guest.h"

namespace Vmm {

Generic_guest::Generic_guest()
: _task(L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Vm>(),
                     "Allocate guest task capability"))
{
  // create the VM task
  auto *e = L4Re::Env::env();
  auto ret = e->factory()->create(_task.get(), L4_PROTO_VM);

  if (l4_error(ret) < 0)
    {
      Err().printf("Cannot create guest VM. Virtualization support may be missing.\n");
      L4Re::chksys(ret, "Create VM task.");
    }
  l4_debugger_set_object_name(_task.get().cap(), "vm-task");
}

void
Generic_guest::register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> const &dev,
                                    Region_type type,
                                    Vdev::Dt_node const &node, size_t index)
{
  l4_uint64_t base, size;
  Dtb::Reg_flags flags;
  int res = node.get_reg_val(index, &base, &size, &flags);
  if (res < 0)
    {
      Err().printf("Failed to read 'reg' with index %zu from node %s: %s\n",
                   index, node.get_name(), node.strerror(res));
      L4Re::throw_error(
        -L4_EINVAL,
        "Node has not enough reg property entries for given index.");
    }

  if (!flags.is_mmio())
    {
      Err()
        .printf("Invalid 'reg' property at index %zu of node %s: not an mmio region\n",
                index, node.get_name());
      L4Re::throw_error(-L4_EINVAL, "Reg property contains no MMIO region.");
    }

  add_mmio_device(Region::ss(Vmm::Guest_addr(base), size, type), dev);

  info().printf("New mmio mapping: @ %llx %llx\n", base, size);
}
} // namespace
