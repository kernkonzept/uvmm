/*
 * Copyright (C) 2017, 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/sys/l4int.h>
#include <l4/sys/types.h>

#include "device.h"
#include "mem_access.h"

namespace Vmm {

struct Io_device : virtual Vdev::Dev_ref
{
  virtual ~Io_device() = 0;

  virtual void io_in(unsigned port, Mem_access::Width width,
                     l4_uint32_t *value) = 0;
  virtual void io_out(unsigned port, Mem_access::Width width,
                      l4_uint32_t value) = 0;

  virtual char const *dev_name() const = 0;

  virtual char const *dev_info(char *buf, size_t size) const
  {
    if (size > 0)
      {
        strncpy(buf, dev_name(), size);
        buf[size - 1] = '\0';
      }
    return buf;
  };
};

inline Io_device::~Io_device() = default;

}
