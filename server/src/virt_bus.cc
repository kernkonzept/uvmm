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
  if (!node.has_compatible())
    return nullptr;

  int num_compatible = node.stringlist_count("compatible");

  for (int c = 0; c < num_compatible; ++c)
    {
      auto *hid = node.stringlist_get("compatible", c, nullptr);
      assert(hid);

      for (auto &iodev: _devices)
        if (!iodev.proxy && iodev.io_dev.is_compatible(hid) > 0)
          {
            auto *regs = node.get_prop<fdt32_t>("reg", nullptr);
            if (!regs)
              return &iodev;

            for (unsigned i = 0; i < iodev.dev_info.num_resources; ++i)
              {
                l4vbus_resource_t res;
                L4Re::chksys(iodev.io_dev.get_resource(i, &res));

                char const *resname = reinterpret_cast<char const *>(&res.id);

                if (res.type != L4VBUS_RESOURCE_MEM || strncmp(resname, "reg0", 4))
                  continue;

                l4_uint64_t base, size;
                if (node.get_reg_val(0, &base, &size) < 0)
                  continue;

                if (base == res.start)
                  return &iodev;
              }
          }
    }

  return nullptr;
}

} // namespace
