/*
 * Copyright (C) 2022,2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "pm_device_if.h"

namespace Vdev {

cxx::unique_ptr<Pm_device_registry> Pm_device_registry::_self;

void
Pm_device_registry::add(Pm_device *dev)
{
  _devices.push_back(dev);
}

void
Pm_device_registry::remove(Pm_device *dev)
{
  for (auto it = _devices.begin(); it != _devices.end(); ++it)
    {
      if (*it == dev)
        {
          _devices.erase(it);
          break;
        }
    }
}

void
Pm_device_registry::suspend() const
{
  for (auto &d : _devices)
    d->pm_suspend();
}

void
Pm_device_registry::resume() const
{
  for (auto &d : _devices)
    d->pm_resume();
}

} // namespace Vdev
