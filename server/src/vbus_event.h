/*
 * Copyright (C) 2017-2018, 2024-2025 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/cxx/ipc_server>
#include <l4/re/error_helper>
#include <l4/re/util/event>
#include <l4/vbus/vbus>

#include <map>

class Vbus_stream_id_handler
{
public:
  virtual void handle_event(L4Re::Event_buffer::Event *e) = 0;
};

/**
 * Interface for incoming vbus events.
 *
 * This class may handle any incoming vbus events such as inhibitor events or
 * input events.
 *
 * We receive events from the vbus and distribute them to their respective
 * stream handlers. Unhandled events are discarded.
 */
class Vbus_event: public L4::Irqep_t<Vbus_event>
{
public:
  Vbus_event(L4::Cap<L4Re::Event> vbus, L4::Registry_iface *registry);

  void handle_irq();

  static void register_stream_id_handler(l4_umword_t stream_id,
                                         Vbus_stream_id_handler *handler)
  {
    if (auto h = _stream_id_handlers.find(stream_id);
             h != _stream_id_handlers.end())
      Dbg(Dbg::Core, Dbg::Warn, "vbus_event")
        .printf("Overwriting handler for stream_id 0x%lx\n",
                stream_id);
    _stream_id_handlers[stream_id] = handler;
  }

private:
  L4Re::Util::Event _vbus_event;
  static std::map<l4_umword_t, Vbus_stream_id_handler *> _stream_id_handlers;
};
