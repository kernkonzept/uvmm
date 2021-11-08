/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */

#include <l4/util/port_io.h>
#include "io_port_handler.h"

namespace Vdev {

void Io_port_handler::io_in(unsigned p, Mem_access::Width width, l4_uint32_t *value)
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

void Io_port_handler::io_out(unsigned p, Mem_access::Width width, l4_uint32_t value)
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

} // namespace Vdev
