/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *         Adam Lackorzynski <adam@l4re.org>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/re/env>
#include "debug.h"
#include "vbus_event.h"

static Dbg warn(Dbg::Pm, Dbg::Warn, "vbus_event");

Vbus_event::Vbus_event()
{
  auto vbus = L4Re::Env::env()->get_cap<L4Re::Event>("vbus");

  if (!vbus)
    return;

  if (_vbus_event.init<L4::Irq>(vbus))
    warn.printf("Failed to initialize vbus events\n");
}

void
Vbus_event::handle_irq()
{
  L4Re::Event_buffer::Event *e;
  while ((e = _vbus_event.buffer().next()))
    e->free();
}

