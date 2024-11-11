/*
 * Copyright (C) 2017-2018 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/cxx/ipc_server>
#include <l4/re/error_helper>
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
  Vbus_event(L4::Cap<L4Re::Event> vbus, L4::Registry_iface *registry);

  void handle_irq();

private:
  L4Re::Util::Event _vbus_event;
};
