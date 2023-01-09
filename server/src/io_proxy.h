/*
 * Copyright (C) 2016-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <vector>

#include <l4/vbus/vbus>

#include "debug.h"
#include "device.h"
#include "irq_svr.h"
#include "virt_bus.h"

namespace Vdev {

class Io_proxy : public Device
{
  class Io_irq_svr : public Irq_svr
  {
  public:
    using Irq_svr::Irq_svr;

    unsigned get_io_irq() const
    { return _irq_num; }
  };

public:
  Io_proxy(L4vbus::Device const &dev)
  : _dev(dev)
  {}

  /**
   * Prepare the factory for creation of physical devices.
   *
   * \param devs  Pointer to Device_lookup interface used to prepare the factory
   *
   * To create non-virtual devices there might be some additional preparations
   * needed. This method has to be invoked before trying to create non-physical
   * devices.
   */
  static void prepare_factory(Device_lookup const *devs);

  bool check_and_bind_irqs(Device_lookup *devs, Dt_node const &node);

  void bind_irq(Vmm::Guest *vmm, Vmm::Virt_bus *vbus,
                cxx::Ref_ptr<Gic::Ic> const &ic,
                unsigned dt_irq, unsigned io_irq, char const *dev_name);

private:
  L4vbus::Device _dev;
  std::vector<cxx::Ref_ptr<Io_irq_svr>> _irqs;
};

} // namespace
