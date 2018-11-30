/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cstring>

#include "device_tree.h"
#include "virt_bus.h"
#include "guest.h"

namespace Vmm {

void
Virt_bus::scan_bus()
{
  L4vbus::Device root = _bus->root();
  Devinfo info;

  while (root.next_device(&info.io_dev, L4VBUS_MAX_DEPTH, &info.dev_info) == 0)
    _devices.push_back(info);
}


Virt_bus::Devinfo *
Virt_bus::find_unassigned_dev(Vdev::Dt_node const &node)
{
  int num_compatible = node.stringlist_count("compatible");

  for (int i = 0; i < num_compatible; ++i)
    {
      auto *hid = node.stringlist_get("compatible", i, nullptr);

      for (auto &iodev: _devices)
        if (!iodev.proxy && iodev.io_dev.is_compatible(hid) > 0)
          return &iodev;
    }

  return 0;
}

} // namespace
