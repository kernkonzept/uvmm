/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once
#include <l4/re/util/object_registry>
#include <l4/re/error_helper>
#include <l4/cxx/ipc_server>
#include <l4/re/util/event>
/**
 * Interface for incoming vbus events.
 *
 * This class may handle any incoming vbus events such as inhibitor events or
 * input events.
 *
 * Currently it just discards incoming events.
 */
class Vbus_event: public L4::Irqep_t<Vbus_event>
{
public:
  Vbus_event();

  void handle_irq();

  L4::Cap<L4::Irq> event_irq() const
  { return L4::cap_cast<L4::Irq>(_vbus_event.irq()); }

  void register_obj(L4::Registry_iface *registry)
  {
    if (!_vbus_event.irq().is_valid())
      return;

    L4Re::chkcap(registry->register_obj(this, L4::cap_cast<L4::Irq>(_vbus_event.irq())),
                 "Registering guest IRQ in proxy");
  }

private:
  L4Re::Util::Event _vbus_event;
};
