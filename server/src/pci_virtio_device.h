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

namespace Vdev { namespace Pci {

/**
 * Virtio device using the Virtio PCI transport employing MSI-X.
 */
template<typename DEV>
class Virtio_device_pci
: public Virt_pci_device
{
  unsigned _device_config_len;

public:
  /**
   * Create virtual PCI device and configure capabilites.
   *
   * The device is constructed in two steps. This constructer initializes the
   * generic PCI device parts of the virtio related stuff. Once the concrete
   * device (that has been derived from this class) has finished its setup, it
   * must call init_virtio_pci_device() to complete the PCI transport related
   * initialization.
   *
   * \param num_msix_entries  Maximum number of MSI-X entries to handle.
   */
  Virtio_device_pci(Vdev::Dt_node const &node, unsigned num_msix_entries)
  : Virt_pci_device(node)
  {
    // BAR[0] is the MSI-X table 32-bit BAR
    check_msix_bar_constraints();
    create_msix_cap(num_msix_entries, 0);

    // BAR[1] is the Virtio config space in I/O space
    check_config_space_constraints();
    Virtio_pci_cap *cap = create_vio_pci_cap_common_entry(nullptr, 1);
    cap = create_vio_pci_cap_notify_entry(cap, 1);
    cap = create_vio_pci_cap_isr_entry(cap, 1);
    cap = create_vio_pci_cap_pci_entry(cap, 1);

    // Check actual I/O BAR usage vs configured I/O BAR size
    l4_uint32_t bar_length = cap->offset + cap->length;
    if (bar_length > bars[1].size)
      {
        Err().printf("Actual size greater configured size due to alignment: "
                     "0x%x > 0x%llx\n",
                     bar_length, bars[1].size);
        L4Re::chksys(-L4_EINVAL, "Configure greater I/O bar size.");
      }

    // Must be the last cap created!
    cap = create_vio_pci_cap_device_entry(cap, 1);
    _device_config_len = cap ? (bars[1].size - cap->offset) : 0;

    dbg().printf("Virtio_device_pci: device configured\n");
  }

  /**
   * Complete the initialization of the virtio PCI transport bits.
   *
   * This method must be called after the concrete virtio device has been
   * setup. It will up-call to the derived class to gather required PCI
   * related information of the device.
   *
   * \pre The virtio config page must be valid. Call register_irq() before this.
   */
  void init_virtio_pci_device()
  {
    auto dev_cfg = dev()->virtio_cfg();
    assert(dev_cfg);
    auto * const hdr = get_header<Pci_header::Type0>();
    hdr->vendor_id = Virtio_pci_device_vendor_id;
    // PCI device_id is calculated by Virtio Device ID + 0x1040
    // (see virtio 1.0 cs4)
    hdr->device_id = Virtio_pci_device_id_base + dev_cfg->device;
    hdr->revision_id = Non_transitional_device_pci_revision_id;
    hdr->subsystem_id = Virtio_pci_subsystem_id_minimum;
    // hdr->subsystem_id && hdr->subsystem_vendor: virtio spec 1.0 cs4: optional
    hdr->status = Interrupt_status_bit | Capability_list_bit;
    hdr->header_type = Multi_func_bit;

    switch (dev_cfg->device)
      {
      case L4VIRTIO_ID_NET:
        hdr->classcode[2] = 0x02;
        break;
      case L4VIRTIO_ID_BLOCK:
        hdr->classcode[2] = 0x01;
        break;
      case L4VIRTIO_ID_CONSOLE:
        // same as used by qemu (communication controller, other)
        hdr->classcode[2] = 0x07;
        hdr->classcode[1] = 0x80;
        break;
      default:
        break;
      }
  }

  bool msix_enabled()
  {
    parse_msix_cap();
    return has_msix? msix_cap.ctrl.enabled() : false;
  }

protected:
  /**
   * The length of the device specific configuration area.
   */
  unsigned device_config_len() const { return _device_config_len; }

private:
  Virtio_pci_cap *
  create_vio_pci_cap_common_entry(Virtio_pci_cap *prev, unsigned io_bar)
  {
    auto *entry   = create_pci_cap<Virtio_pci_common_cap>();
    entry->bar    = io_bar;
    // Start the IObar with the PCI common config
    entry->offset = prev ? prev->offset + prev->length : 0;
    entry->length = sizeof(Virtio_pci_common_cfg);

    return entry;
  }

  Virtio_pci_cap *
  create_vio_pci_cap_notify_entry(Virtio_pci_cap *prev, unsigned io_bar)
  {
    auto *entry   = create_pci_cap<Virtio_pci_notify_cap>();
    entry->bar    = io_bar;
    // offset must be 2 byte aligned
    entry->offset = prev ? l4_round_size(prev->offset + prev->length, 1) : 0;
    entry->length = 2; // smallest possible length

    entry->notify_off_multiplier = 0;

    return entry;
  }

  Virtio_pci_cap *create_vio_pci_cap_isr_entry(Virtio_pci_cap *prev,
                                               unsigned io_bar)
  {
    auto *entry   = create_pci_cap<Virtio_pci_isr_cap>();
    entry->bar    = io_bar;
    entry->offset = prev ? prev->offset + prev->length : 0;
    entry->length = 2;

    return entry;
  }

  /// The device cap uses the rest of the IO bar. Must be the last cap created.
  Virtio_pci_cap *create_vio_pci_cap_device_entry(Virtio_pci_cap *prev,
                                                  unsigned io_bar)
  {
    // 4 byte align offset to find device specific config
    unsigned entry_start =
      prev ? l4_round_size(prev->offset + prev->length, 2) : 0;

    if (entry_start >= bars[io_bar].size)
      return nullptr;

    auto *entry   = create_pci_cap<Virtio_pci_device_cap>();
    entry->bar    = io_bar;
    entry->offset = entry_start;
    entry->length = bars[io_bar].size - entry_start;

    return entry;
  }

  Virtio_pci_cap *create_vio_pci_cap_pci_entry(Virtio_pci_cap *prev,
                                               unsigned io_bar)
  {
    auto *entry   = create_pci_cap<Virtio_pci_cfg_cap>();
    entry->bar    = io_bar;
    entry->offset = prev ? prev->offset + prev->length : 0;
    entry->length = sizeof(Virtio_pci_cfg_cap);

    // TODO This is not fully implemented. But the spec forces me to provide
    // the cap.
    return entry;
  }

  /**
   * Allocate an entry in the PCI capability list of the PCI configuration
   * header and fill it with the MSI-X capability.
   *
   * \param max_msix_entries  Maximum number of MSI-X entries of this device.
   * \param BAR index         BAR index[0,5] of the MSI-X memory BAR.
   */
  void create_msix_cap(unsigned max_msix_entries, unsigned bar_index)
  {
    assert(bar_index < 6);

    Pci_msix_cap *cap    = create_pci_cap<Pci_msix_cap>();
    cap->ctrl.enabled()  = 1;
    cap->ctrl.masked()   = 0;
    cap->ctrl.max_msis() = max_msix_entries - 1;
    cap->tbl.bir()       = bar_index;
    cap->pba.offset()    = L4_PAGESIZE >> 3;
    cap->pba.bir()       = bar_index;

    dbg().printf("msi.msg_ctrl 0x%x\n", cap->ctrl.raw);
    dbg().printf("msi.table 0x%x\n", cap->tbl.raw);
    dbg().printf("msi.pba 0x%x\n", cap->pba.raw);
    dbg().printf("Size of MSI-X cap 0x%lx\n", sizeof(*cap));
  }

  inline void
  check_msix_bar_constraints()
  {
    if (bars[0].type != Pci_cfg_bar::MMIO32)
      L4Re::throw_error(-L4_EINVAL, "BAR[0] is a MMIO(32) entry.");

    if (bars[0].size < Msix_mem_need)
      {
        Err().printf("At least 0x%x Bytes of MSI-X memory are configured.\n",
                     Msix_mem_need);
        L4Re::throw_error(-L4_EINVAL, "More MSI-X memory necessary.");
      }
  }

  inline void
  check_config_space_constraints()
  {
    if (bars[1].type != Pci_cfg_bar::IO)
      L4Re::chksys(-L4_EINVAL, "BAR[1] is an IO entry.");

    if (bars[1].size < Num_pci_connector_ports)
      {
        Err().printf("Configured IO ports are a power of 2 >= 0x%x.\n",
                     Num_pci_connector_ports);
        L4Re::chksys(-L4_EINVAL, "More IO ports necessary.");
      }
  }

  DEV *dev() { return static_cast<DEV *>(this); }
  DEV const *dev() const { return static_cast<DEV const *>(this); }
}; // class Virtio_device_pci


} } // namespace Vdev::Pci
