/*
 * Copyright (C) 2017-2018, 2020 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernekonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public License,
 * version 2. Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "irq.h"
#include "irq_dt.h"
#include "virtio_dev.h"

namespace Virtio {

/**
 * This IRQ event connector supports a single IRQ for all events.
 *
 * In general, the event connector connects the events issued by a
 * virtio device with the interrupt configured in the transport layer.
 * The connector makes the virtio device independent from the transport
 * specific event notification facility, e.g. Interrupt or MSI.
 */
class Event_connector_irq
{
public:
  /**
   * Commit / send events marked in `ev` to the guest.
   *
   * \param ev  Set of pending events to be injected into the guest.
   */
  void send_events(Virtio::Event_set &&ev)
  {
    if (ev.e)
      _sink.inject();

    ev.reset();
  }

  /// Send a single event with index `idx` to the guest.
  void send_event(l4_uint16_t /* idx */)
  {
    _sink.inject();
  }

  /**
   * Acknowledge the bits set in the bit mask.
   *
   * \param irq_ack_mask  Describes the config/queue events to acknowledge.
   */
  void clear_events(unsigned /* irq_ack_mask */)
  {
    _sink.ack();
  }

  /**
   * Line-based IRQ setup routine for device-tree setup.
   */
  int init_irqs(Vdev::Device_lookup *devs, Vdev::Dt_node const &node)
  {
    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) < 0 || !it.ic_is_virt())
      return -1;

    _sink.rebind(it.ic(), it.irq());
    return 0;
  }

private:
  Vmm::Irq_sink _sink;
};

} // namespace Virtio
