/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernekonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public License,
 * version 2. Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "irq.h"
#include "virtio_dev.h"

namespace Virtio {

/**
 * Connect the events issued by a virtio_device with the interrupt configured
 * in the transport layer.
 *
 * The connector makes the virtio device independent from the transport
 * specific event notification facility, e.g. Interrupt or MSI.
 *
 * This specific connector supports a single IRQ for all events.
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

  /**
   * Acknowledge the bits set in the bit mask.
   *
   * \param irq_ack_mask  Describes the config/queue event to acknowledge.
   */
  void clear_events(unsigned irq_ack_mask)
  {
    (void)irq_ack_mask;
    _sink.ack();
  }

  /**
   * Line-based IRQ setup routine for device-tree setup.
   */
  int init_irqs(Vdev::Device_lookup const *devs,
                Vdev::Dt_node const &dev_node)
  {
    auto irq_ctl = dev_node.find_irq_parent();
    if (!irq_ctl.is_valid())
      return -L4_ENODEV;

    // XXX need dynamic cast for Ref_ptr here
    auto *ic = dynamic_cast<Gic::Ic *>(devs->device_from_node(irq_ctl).get());

    if (!ic)
      L4Re::chksys(-L4_ENODEV, "Interupt handler for virtio console has bad type.\n");

    _sink.rebind(ic, ic->dt_get_interrupt(dev_node, 0));
    return 0;
  }

private:
  Vmm::Irq_sink _sink;
};

} // namespace Virtio
