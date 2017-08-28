/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
/**
 * Base class definition for devices using the Virtio PCI transport.
 */
#pragma once

#include <cassert>

#include <l4/re/env>
#include <l4/re/rm>
#include <l4/re/error_helper>
#include <l4/cxx/exceptions>

#include "debug.h"
#include "pci_device.h"
#include "io_device.h"
#include "virtio_dev.h"
#include "pci_virtio_config.h"
#include "virtio_qword.h"

namespace Vdev {

/**
 * Virtio device using the Virtio PCI transport employing MSI-X.
 */
template<typename DEV>
class Virtio_device_pci
: public Pci_device_msix
{
public:
  /**
   * Late configuration to allow Virtio_proxy to connect to l4virtio device
   * first. Call this after register_irq().
   *
   * \param regs              Array of BAR entries.
   * \param regs_size         Array size.
   * \param num_msix_entries  Maximum number of MSI-X entries to handle.
   */
  void configure(cxx::static_vector<Device_register_entry> const &regs,
                 unsigned num_msix_entries)
  {
    config_device(regs, num_msix_entries);
    dbg().printf("Virtio_device_pci: device configured\n");
  }

private:
  void set_space(unsigned bar, l4_uint32_t value, l4_size_t sz, bool io)
  {
    io ? set_io_space<Pci_header::Type0>(bar, value, sz)
       : set_mem_space<Pci_header::Type0>(bar, value, sz);
  }

  void config_device(cxx::static_vector<Device_register_entry> const &regs,
                     unsigned num_msix_entries)
  {
    auto dev_cfg = dev()->virtio_cfg();
    assert(dev_cfg);
    auto * const hdr = get_header<Pci_header::Type0>();
    hdr->vendor_id = Virtio_pci_device_vendor_id;
    // PCI device_id is calculated by Virtio Device ID + 0x1040
    // (see virtio 1.0 cs4)
    hdr->device_id = Virtio_pci_device_id_base + dev_cfg->device;
    hdr->revision_id = Non_transitional_device_pci_revision_id;
    hdr->subsystem_id = dev_cfg->device;
    // hdr->subsystem_id && hdr->subsystem_vendor: virtio spec 1.0 cs4: optional
    hdr->command = Io_space_bit;
    hdr->status = Interrupt_status_bit | Capability_list_bit;
    hdr->header_type = Multi_func_bit;

    unsigned io_bar = -1U;
    for (unsigned i = 0; i < regs.size(); ++i)
      {
        auto &reg = regs[i];
        bool io_space = reg.flags & Dt_pci_flags_io;

        // Ensure reserved bits are unused.
        if (reg.base & (io_space ? 0x3 : 0xf))
          L4Re::chksys(-L4_EINVAL, "Aligned BAR memory.");

        // XXX assumption one IO-Port bar and one MMIO MSIX bar
        if (!io_space)
          {
            reg.print();
            assert(reg.size >= Msix_mem_need);
          }

        set_space(i, reg.base, reg.size, io_space);
        Dbg().printf("Virtio pci config BAR%i: 0x%x\n", i,
                     hdr->base_addr_regs[i]);

        if (!io_space)
          create_msix_cap(num_msix_entries, i);
        else
          io_bar = i;
      }

    if (io_bar == -1U)
      L4Re::chksys(-L4_EINVAL, "Expected one IO BAR for a VirtIO-PCI device.");

    Virtio_pci_cap_base *cap = create_vio_pci_cap_common_entry(nullptr, io_bar);
    cap = create_vio_pci_cap_notify_entry(cap, io_bar);
    cap = create_vio_pci_cap_isr_entry(cap, io_bar);
    // TODO implement create_vio_pci_cap_device_entry
    // cap = create_vio_pci_cap_device_entry(cap, io_bar);
    cap = create_vio_pci_cap_pci_entry(cap, io_bar);
  }

  Virtio_pci_cap_base *
  create_vio_pci_cap_common_entry(Virtio_pci_cap_base *prev, unsigned io_bar)
  {
    auto *entry = allocate_pci_cap<Virtio_pci_cap>();
    entry->id.cap_type  = Virtio_pci_cap_vndr;
    entry->vio.cap_len  = sizeof(Virtio_pci_cap);
    entry->vio.cfg_type = Virtio_pci_cap_common_cfg;
    entry->vio.bar      = io_bar;
    // Start the IObar with the PCI common config
    entry->vio.offset   = prev ? prev->offset + prev->length : 0;
    entry->vio.length   = sizeof(Virtio_pci_common_cfg);

    return &entry->vio;
  }

  Virtio_pci_cap_base *
  create_vio_pci_cap_notify_entry(Virtio_pci_cap_base *prev, unsigned io_bar)
  {
    auto *entry = allocate_pci_cap<Virtio_pci_notify_cap>();
    entry->id.cap_type  = Virtio_pci_cap_vndr;
    entry->vio.cap_len  = sizeof(Virtio_pci_notify_cap);
    entry->vio.cfg_type = Virtio_pci_cap_notify_cfg;
    entry->vio.bar      = io_bar;
    // offset must be 2 byte aligned
    entry->vio.offset =
      prev ? l4_round_size(prev->offset + prev->length, 1) : 0;
    entry->vio.length   = 2; // smallest possible length

    entry->notify_off_multiplier = 0;

    return &entry->vio;
  }

  Virtio_pci_cap_base *create_vio_pci_cap_isr_entry(Virtio_pci_cap_base *prev,
                                                    unsigned io_bar)
  {
    auto *entry = allocate_pci_cap<Virtio_pci_cap>();
    entry->id.cap_type  = Virtio_pci_cap_vndr;
    entry->vio.cap_len  = sizeof(Virtio_pci_cap);
    entry->vio.cfg_type = Virtio_pci_cap_isr_cfg;
    entry->vio.bar      = io_bar;
    entry->vio.offset   = prev ? prev->offset + prev->length : 0;
    entry->vio.length   = 2;

    return &entry->vio;
  }

  Virtio_pci_cap_base *
  create_vio_pci_cap_device_entry(Virtio_pci_cap_base *prev, unsigned io_bar)
  {
    // 4 byte align offset to find device specific config
    // Should probably be set up by the device separately?
    return prev;
  }

  Virtio_pci_cap_base *create_vio_pci_cap_pci_entry(Virtio_pci_cap_base *prev,
                                                    unsigned io_bar)
  {
    auto *entry = allocate_pci_cap<Virtio_pci_cfg_cap>();
    entry->id.cap_type  = Virtio_pci_cap_vndr;
    entry->vio.cap_len  = sizeof(Virtio_pci_cfg_cap);
    entry->vio.cfg_type = Virtio_pci_cap_pci_cfg;
    entry->vio.bar      = io_bar;
    entry->vio.offset   = prev ? prev->offset + prev->length : 0;
    entry->vio.length   = sizeof(Virtio_pci_cfg_cap);

    // TODO This is not fully implemented. But the spec forces me to provide
    // the cap.
    return &entry->vio;
  }

  DEV *dev() { return static_cast<DEV *>(this); }
  DEV const *dev() const { return static_cast<DEV const *>(this); }
}; // class Virtio_device_pci

} // namespace Vdev
