/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#pragma once

#include <l4/cxx/ref_ptr>

#include "debug.h"
#include "irq.h"

namespace Vdev {

/**
 * Interrupt passthrough.
 *
 * Forwards L4Re interrupts to an Irq_sink.
 */
class Irq_svr
: public Gic::Eoi_handler,
  public L4::Irqep_t<Irq_svr>,
  public cxx::Ref_obj
{
public:
  Irq_svr(unsigned io_irq) : _io_irq{io_irq} {}

  ~Irq_svr() noexcept
  {
    unbind_eoi_handler();
  }

  void set_sink(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq)
  {
    unbind_eoi_handler();
    _irq.rebind(ic, irq);
    _irq.set_eoi_handler(this);
  }

  void set_eoi(L4::Cap<L4::Irq_eoi> eoi)
  { _eoi = eoi; }

  void handle_irq()
  { _irq.inject(); }

  void eoi() override
  {
    _irq.ack();
    _eoi->unmask(_io_irq);
  }

  unsigned get_io_irq() const
  { return _io_irq; }

private:
  void unbind_eoi_handler() const
  { _irq.set_eoi_handler(nullptr); }

  Vmm::Irq_sink _irq;
  unsigned _io_irq;
  L4::Cap<L4::Irq_eoi> _eoi;
};

} // namespace
