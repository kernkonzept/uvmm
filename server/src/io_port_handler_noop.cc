/*
 * Copyright (C) 2021, 2024 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <cassert>
#include "io_port_handler.h"

namespace Vdev {

void Io_port_handler::io_in(unsigned, Mem_access::Width, l4_uint32_t *)
{
  assert(false);
}

void Io_port_handler::io_out(unsigned, Mem_access::Width, l4_uint32_t)
{
  assert(false);
}

} // namespace Vdev
