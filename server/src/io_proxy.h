/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>
#include <vector>

#include <l4/cxx/ref_ptr>
#include <l4/vbus/vbus>

#include "debug.h"
#include "device.h"
#include "irq.h"

namespace Vdev {

/**
 * Interrupt passthrough.
 *
 * Forwards L4Re interrupts to an Irq_sink.
 */
class Irq_svr
: public Gic::Irq_source,
  public L4::Irqep_t<Irq_svr>
{
public:
  Irq_svr(unsigned io_irq) : _io_irq{io_irq} {}

  void set_sink(Gic::Ic *ic, unsigned irq)
  { _irq.rebind(ic, irq); }

  void handle_irq()
  { _irq.inject(); }

  void eoi() override
  {
    _irq.ack();
    obj_cap()->unmask();
  }

  unsigned get_io_irq() const
  { return _io_irq; }

private:
  Vmm::Irq_sink _irq;
  unsigned _io_irq;
};

class Io_proxy : public Device
{
public:
  Io_proxy(L4vbus::Device const &dev)
  : _dev(dev)
  {}

  void init_device(Device_lookup const *devs, Dt_node const &self) override;

  static int decode_resource_id(char c);

private:
  void bind_irq(Vmm::Guest *vmm, Vmm::Virt_bus *vbus, Gic::Ic *ic,
                Dt_node const &self, unsigned dt_idx, unsigned io_irq);

  L4vbus::Device _dev;
};

} // namespace
