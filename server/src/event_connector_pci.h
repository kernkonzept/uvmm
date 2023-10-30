/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"
#include "msi_controller.h"
#include "msix.h"
#include "virtio_event_connector.h"
#include "ds_mmio_mapper.h"
#include "guest.h"

namespace Virtio {

/**
 * This MSIX connector supports sending MSIs configured in the MSI-X table.
 *
 * For further documentation look at Event_connector_irq.
 */
class Event_connector_msix
{
public:
  Event_connector_msix(Gic::Msix_dest const &msix_dest)
  : _msix_dest(msix_dest),
    _msix_mem(make_ram_ds_handler(Vdev::Pci::Msix_mem_need,
                                  L4Re::Mem_alloc::Continuous))
  {}

  void send_events(Virtio::Event_set &&ev)
  {
    for (unsigned i = 0; ev.e != 0; ev.e >>= 1, ++i)
      if (ev.e & 1)
        send_event(i);
  }

  void send_event(l4_uint16_t idx) const
  {
    auto const *entry = msix_entry(idx);
    if (!entry->masked())
      _msix_dest.send_msix(entry->addr, entry->data);
  }

  void clear_events(unsigned) {}

  /**
   * Create virtual device to let guest access MSI-X table.
   */
  cxx::Ref_ptr<Vmm::Mmio_device> make_mmio_device() const
  {
    return Vdev::make_device<Ds_handler>(_msix_mem);
  }

private:
  Gic::Msix_dest _msix_dest;
  cxx::Ref_ptr<Vmm::Ds_manager> _msix_mem;

  Vdev::Msix::Table_entry *msix_entry(l4_uint16_t idx) const
  {
    return &_msix_mem->local_addr<Vdev::Msix::Table_entry *>()[idx];
  }

  // I can use RW MMIO memory, as I am the endpoint for the guest configuration
  // of the MSIs and evaluate the entries every time, an event should be sent.
  cxx::Ref_ptr<Vmm::Ds_manager> make_ram_ds_handler(l4_size_t size,
                                                    unsigned long flags)
  {
    L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap ds
      = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>(),
                     "Allocate DS cap for DS-handler memory.");

    L4Re::chksys(L4Re::Env::env()->mem_alloc()->alloc(size, ds.get(), flags),
                 "Allocate memory in dataspace.");

    return cxx::make_ref_obj<Vmm::Ds_manager>("Event_connector_msix", ds, 0,
                                              size);
  }

}; // class Event_connector_msix

} // namespace Virtio
