/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>

#include "device.h"
#include "io_device.h"

namespace Vdev {

using namespace Vmm;

class Io_port_handler : public Io_device, public Device
{
  unsigned _base;

public:
  Io_port_handler(unsigned port_base)
  : _base(port_base)
  {}

  void io_in(unsigned p, Mem_access::Width width, l4_uint32_t *value);
  void io_out(unsigned p, Mem_access::Width width, l4_uint32_t value);
}; // class Io_port_handler

} // namespace Vdev
