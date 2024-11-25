/*
 * Copyright (C) 2017-2018, 2024 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *         Adam Lackorzynski <adam@l4re.org>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "debug.h"
#include "vbus_event.h"

static Dbg warn(Dbg::Pm, Dbg::Warn, "vbus_event");
std::map<l4_umword_t, Vbus_stream_id_handler *> Vbus_event::_stream_id_handlers;

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
    {
      auto handler = _stream_id_handlers.find(e->payload.stream_id);
      if (handler != _stream_id_handlers.end())
        handler->second->handle_event(e);
      e->free();
    }
}

