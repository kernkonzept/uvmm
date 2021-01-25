/*
 * Copyright (C) 2017-2018 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *         Adam Lackorzynski <adam@l4re.org>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include "debug.h"
#include "vbus_event.h"

static Dbg warn(Dbg::Pm, Dbg::Warn, "vbus_event");

Vbus_event::Vbus_event(L4::Cap<L4Re::Event> vbus, L4::Registry_iface *registry)
{
  if (!vbus)
    return;

  if (_vbus_event.init<L4::Irq>(vbus))
    {
      warn.printf("Failed to initialize vbus events.\n");
      return;
    }

  L4Re::chkcap(registry->register_obj(this,
                                      L4::cap_cast<L4::Irq>(_vbus_event.irq())),
               "Register event IRQ for vbus events");
}

void
Vbus_event::handle_irq()
{
  L4Re::Event_buffer::Event *e;
  while ((e = _vbus_event.buffer().next()))
    e->free();
}

