/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/error_helper>

#include "device.h"
#include "irq.h"

namespace Vdev {

struct Core_timer : public Device, public Vmm::Irq_edge_sink
{
  void init_device(Device_lookup const *devs, Dt_node const &self) override
  {
    auto irq_ctl = self.find_irq_parent();
    if (!irq_ctl.is_valid())
      L4Re::chksys(-L4_ENODEV, "No interupt handler found for timer.\n");

    // XXX need dynamic cast for Ref_ptr here
    auto *ic = dynamic_cast<Gic::Ic *>(devs->device_from_node(irq_ctl).get());

    if (!ic)
      L4Re::chksys(-L4_ENODEV, "Interupt handler for timer has bad type.\n");

    rebind(ic, ic->dt_get_interrupt(self, 2));
  }
};


}
