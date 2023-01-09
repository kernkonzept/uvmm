/*
 * Copyright (C) 2016-2021 Kernkonzept GmbH.
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

class Device_repository
{
public:
  struct Dt_device
  {
    std::string path;
    l4_uint32_t phandle;
    cxx::Ref_ptr<Device> dev;
  };

  cxx::Ref_ptr<Device> device_from_node(Dt_node const &node,
                                        std::string *path = nullptr) const
  {
    // Is a device corresponding to that node already part of the repository?
    // Identify the device using the phandle (if the node contains a phandle)
    // or using the full node node path (otherwise).
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

    // Return the path to the caller for passing to add(). This saves an
    // expensive operation.
    if (path)
      path->assign(buf);

    return cxx::Ref_ptr<Device>();
  }

  void add(Dt_node const &node, cxx::Ref_ptr<Device> dev,
           std::string const &path)
  {
    l4_uint32_t phandle = node.get_phandle();

    if (path.empty())
      {
        char buf[1024];
        node.get_path(buf, sizeof(buf));
        _devices.push_back({buf, phandle, dev});
      }
    else
      _devices.push_back({path, phandle, dev});
  }

  std::vector<Dt_device>::const_iterator begin() const
  { return _devices.begin(); }

  std::vector<Dt_device>::const_iterator end() const
  { return _devices.end(); }

private:
  std::vector<Dt_device> _devices;
};

} // namespace
