/*
 * Copyright (C) 2018, 2020-2021, 2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
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

  char const *dev_name() const override
  { return "Pass-through device"; }

  void io_in(unsigned p, Mem_access::Width width, l4_uint32_t *value) override;
  void io_out(unsigned p, Mem_access::Width width, l4_uint32_t value) override;
}; // class Io_port_handler

} // namespace Vdev
