/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"
#include "msi_distributor.h"
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
  Event_connector_msix(cxx::Ref_ptr<Gic::Msi_distributor> const &distr,
                       unsigned max_msix_entries)
  : _distr(distr),
    _msix_mem(
      make_ram_ds_handler(Vdev::Msix_mem_need, L4Re::Mem_alloc::Continuous)),
    _msix_tbl(_msix_mem->local_start(), max_msix_entries)
  {}

  void send_events(Virtio::Event_set &&ev)
  {
    for (unsigned i = 0; ev.e != 0; ev.e >>= 1, ++i)
      if (ev.e & 1)
        send_event(i);
  }

  void send_event(l4_uint16_t const idx)
  {
    auto entry = _msix_tbl.entry(idx);
    if (!entry.disabled())
      _distr->send(entry.msg);
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
    devs->vmm()->add_mmio_device(Region::ss((l4_addr_t)dt_msi_base,
                                            Vdev::Msix_mem_need),
                                 _msix_mem);
    return 0;
  }

private:
  cxx::Ref_ptr<Gic::Msi_distributor> _distr;
  cxx::Ref_ptr<Ds_handler> _msix_mem;
  Vdev::Msix_table _msix_tbl;

  cxx::Ref_ptr<Ds_handler> make_ram_ds_handler(l4_size_t size,
                                               unsigned long flags)
  {
    // XXX leaking capability, known issue with Ds_handler.
    auto ds = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>(),
                           "Allocate DS cap for DS-handler memory.");

    L4Re::chksys(L4Re::Env::env()->mem_alloc()->alloc(size, ds, flags),
                 "Allocate memory in dataspace.");

    return Vdev::make_device<Ds_handler>(ds, 0, size);
  }

}; // class Event_connector_msix

} // namespace Virtio
