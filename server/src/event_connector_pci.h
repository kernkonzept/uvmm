/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"
#include "msi_controller.h"
#include "msi.h"
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
  Event_connector_msix(cxx::Ref_ptr<Gic::Msix_controller> const &distr)
  : _distr(distr),
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
      _distr->send(entry->addr, entry->data);
  }

  void clear_events(unsigned) {}

  int init_irqs(Vdev::Device_lookup const *devs,
                Vdev::Dt_node const &node)
  {
    l4_uint64_t dt_msi_base = 0, dt_msi_size = 0;
    node.get_reg_val(0, &dt_msi_base, &dt_msi_size);
    // device tree values already checked by factory.create()

    // Registered region must have the address from the DT as this is the value
    // presented by the PCI device to the guest.
    devs->vmm()->add_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(dt_msi_base),
                                                 Vdev::Pci::Msix_mem_need,
                                                 Vmm::Region_type::Virtual),
                                 Vdev::make_device<Ds_handler>(_msix_mem));
    return 0;
  }

private:
  cxx::Ref_ptr<Gic::Msix_controller> _distr;
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

    return cxx::make_ref_obj<Vmm::Ds_manager>(ds, 0, size);
  }

}; // class Event_connector_msix

} // namespace Virtio
