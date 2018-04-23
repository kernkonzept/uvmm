/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/util/port_io.h>

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

  void io_in(unsigned p, Mem_access::Width width, l4_uint32_t *value)
  {
    l4_uint16_t port = p + _base;

    switch(width)
      {
      case Mem_access::Wd8:
        *value = l4util_in8(port);
        break;
      case Mem_access::Wd16:
        *value = l4util_in16(port);
        break;
      case Mem_access::Wd32:
        *value = l4util_in32(port);
        break;
      case Mem_access::Wd64:
        // architecture does not support 64bit port access
        *value = -1;
        break;
      }
  }

  void io_out(unsigned p, Mem_access::Width width, l4_uint32_t value)
  {
    l4_uint16_t port = p + _base;

    switch(width)
      {
      case Mem_access::Wd8:
        l4util_out8(value, port);
        break;

      case Mem_access::Wd16:
        l4util_out16(value, port);
        break;

      case Mem_access::Wd32:
        l4util_out32(value, port);
        break;

      case Mem_access::Wd64:
        // architecture does not support 64bit port access
        break;
      }
  }
}; // class Io_port_handler

} // namespace Vdev
