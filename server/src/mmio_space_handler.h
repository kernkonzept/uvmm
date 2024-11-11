/*
 * Copyright (C) 2017, 2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/re/mmio_space>

#include "mmio_device.h"

namespace Vdev {

class Mmio_space_handler
: public Vmm::Mmio_device_t<Mmio_space_handler>
{
public:
  Mmio_space_handler(L4::Cap<L4Re::Mmio_space> svr, long /* local_start */,
                     long /* size */, long offset = 0)
  : _server(svr), _offset(offset)
  {}

  l4_uint64_t read(unsigned addr, char width, unsigned)
  {
    l4_uint64_t value;

    if (_server->mmio_read(addr + _offset, width, &value) == L4_EOK)
      return value;

    return 0;
  }

  void write(unsigned addr, char width, l4_uint64_t value, unsigned)
  { _server->mmio_write(addr + _offset, width, value); }

  char const *dev_name() const override { return "Mmio_space_handler"; }

private:
  L4::Cap<L4Re::Mmio_space> _server;
  long _offset;
};

}
