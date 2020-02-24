/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/re/error_helper>
#include <l4/re/util/object_registry>

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
  Irq_svr(L4Re::Util::Object_registry *registry, L4::Cap<L4::Icu> icu,
          unsigned irq, cxx::Ref_ptr<Gic::Ic> const &ic, unsigned dt_irq)
  {
    if (ic->get_eoi_handler(dt_irq))
      L4Re::throw_error(-L4_EEXIST, "Bind IRQ for Irq_svr object.");

    L4Re::chkcap(registry->register_irq_obj(this), "Cannot register irq");

    int ret = L4Re::chksys(icu->bind(irq, obj_cap()),
                           "Cannot bind to IRQ");
    switch (ret)
      {
      case 0:
        Dbg(Dbg::Dev, Dbg::Info, "irq_svr")
          .printf("Irq 0x%x will be unmasked directly\n", irq);
        set_eoi(obj_cap());
        break;
      case 1:
        Dbg(Dbg::Dev, Dbg::Info, "irq_svr")
          .printf("Irq 0x%x will be unmasked at ICU\n", irq);
        set_eoi(icu);
        break;
      default:
        L4Re::throw_error(-L4_EINVAL, "Invalid return code from bind to IRQ");
        break;
      }

    _irq_num = irq;

    // Point irq_svr to ic:dt_irq for upstream events (like
    // interrupt delivery)
    _irq.rebind(ic, dt_irq);
    _irq.set_eoi_handler(this);
  }

  ~Irq_svr() noexcept
  {
    unbind_eoi_handler();
  }

  void handle_irq()
  { _irq.inject(); }

  void eoi() override
  {
    _irq.ack();
    _eoi->unmask(_irq_num);
  }

private:
  void set_eoi(L4::Cap<L4::Irq_eoi> eoi)
  { _eoi = eoi; }

  void unbind_eoi_handler() const
  { _irq.set_eoi_handler(nullptr); }

  Vmm::Irq_sink _irq;
  L4::Cap<L4::Irq_eoi> _eoi;
protected:
  unsigned _irq_num;
};

} // namespace
