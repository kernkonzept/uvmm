/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/vbus/vbus>

#include "debug.h"
#include "device.h"
#include "virt_bus.h"

namespace Vdev {

class Io_proxy : public Device
{
public:
  Io_proxy(L4vbus::Device const &dev)
  : _dev(dev)
  {}

  /**
   * Prepare the factory for creation of physical devices.
   *
   * \param devs  Pointer to Device_lookup interface used to prepare the factory
   *
   * To create non virtual devices there might be some additional preparations
   * needed. This method has to be invoked before trying to create non physical
   * devices.
   */
  static void prepare_factory(Device_lookup const *devs);

private:
  L4vbus::Device _dev;
};

} // namespace
