/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <string>
#include <vector>

#include "device.h"
#include "device_tree.h"

namespace Vdev {

class Device_repository : public Device_lookup
{
  struct Dt_device
  {
    std::string path;
    l4_uint32_t phandle;
    cxx::Ref_ptr<Device> dev;
  };

public:
  cxx::Ref_ptr<Device> device_from_node(Dt_node const &node) const override
  {
    l4_uint32_t phandle = node.get_phandle();

    if (phandle != 0 && phandle != -1U)
      {
        for (auto const &d : _devices)
          {
            if (d.phandle == phandle)
              return d.dev;
          }
      }

    char buf[1024];
    node.get_path(buf, sizeof(buf));

    for (auto const &d : _devices)
      {
        if (d.path == buf)
          return d.dev;
      }

    return cxx::Ref_ptr<Device>();
  }

  void add(char const *path, l4_uint32_t phandle, cxx::Ref_ptr<Device> dev)
  { _devices.push_back({path, phandle, dev}); }

  void init_devices(Device_tree dt)
  {
    for (auto &d : _devices)
      {
        Dbg().printf("Init device '%s'.\n", d.path.c_str());

        auto node = dt.invalid_node();
        if (d.phandle != 0 && d.phandle != -1U)
          node = dt.phandle_offset(d.phandle);

        if (!node.is_valid())
          node = dt.path_offset(d.path.c_str());

        d.dev->init_device(this, node);
      }
  }

private:
  std::vector<Dt_device> _devices;
};

} // namespace

