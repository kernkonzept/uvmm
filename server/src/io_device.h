/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/l4int.h>
#include <l4/sys/types.h>

#include "generic_vcpu_ptr.h"
#include "mem_access.h"

namespace Vmm {

struct Io_device : virtual Vdev::Dev_ref
{
  virtual ~Io_device() = 0;

  virtual void io_in(unsigned port, Mem_access::Width width,
                     l4_uint32_t *value) = 0;
  virtual void io_out(unsigned port, Mem_access::Width width,
                      l4_uint32_t value) = 0;
};

inline Io_device::~Io_device() = default;

}
