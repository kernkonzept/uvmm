/*
 * Copyright (C) 2017-2019, 2021-2023 Kernkonzept GmbH.
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
#include "virt_pci_device.h"
#include "io_device.h"
#include "virtio_dev.h"
#include "pci_virtio_config.h"
#include "virtio_qword.h"
#include "device/pci_bridge_windows.h"

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
   * Create virtual PCI device and configure capabilities.
   *
   * The device is constructed in two steps. This constructor initializes the
   * generic PCI device parts of the virtio related stuff. Once the concrete
   * device (that has been derived from this class) has finished its setup, it
   * must call init_virtio_pci_device() to complete the PCI transport related
   * initialization.
   *
   * \param node              Device Tree node of this device.
   * \param num_msix_entries  Maximum number of MSI-X entries to handle.
   */
  Virtio_device_pci(Vdev::Dt_node const &node, unsigned num_msix_entries,
                    Pci_bridge_windows *wnds)
  : Virt_pci_device(node, wnds)
  {
    // There is a 32-bit BAR configured that fits the MSI-X table.
    unsigned msix_bar = msix_bar_idx();
    check_msix_bar_constraints(msix_bar);
    create_msix_cap(num_msix_entries, msix_bar);

    bool mmio_bar = false;
    // There is either an IO BAR or a second MMIO32 BAR configured.
    unsigned virtio_bar = virtio_bar_idx(Pci_cfg_bar::IO);
    if (virtio_bar == -1U)
      {
        virtio_bar = virtio_bar_idx(Pci_cfg_bar::MMIO32);
        if (virtio_bar != -1U)
          mmio_bar = true;
      }

    check_config_space_constraints(virtio_bar, mmio_bar);
    // first VirtIO capability defines the start within the BAR
    Virtio_pci_cap *cap =
      create_vio_pci_cap_common_entry(nullptr, virtio_bar);
    cap = create_vio_pci_cap_notify_entry(cap, virtio_bar);
    cap = create_vio_pci_cap_isr_entry(cap, virtio_bar);
    cap = create_vio_pci_cap_pci_entry(cap, virtio_bar);

    // Check actual I/O BAR usage vs configured I/O BAR size
    l4_uint32_t bar_length = cap->offset + cap->length;
    if (bar_length > bars[virtio_bar].size)
      {
        Err().printf("Actual size greater configured size due to alignment: "
                     "0x%x > 0x%llx\n",
                     bar_length, bars[virtio_bar].size);
        L4Re::chksys(-L4_EINVAL, "Configure greater I/O bar size.");
      }

    // Must be the last cap created!
    cap = create_vio_pci_cap_device_entry(cap, virtio_bar);
    _device_config_len = cap ? cap->length : 0;

    trace().printf("Virtio_device_pci: device configured\n");
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
        hdr->classcode[2] = Pci_class_code_network_device;
        break;
      case L4VIRTIO_ID_BLOCK:
      case L4VIRTIO_ID_SCSI:
        hdr->classcode[2] = Pci_class_code_mass_storage_device;
        break;
      case L4VIRTIO_ID_CONSOLE:
        // same as used by qemu (communication controller, other)
        hdr->classcode[2] = Pci_class_code_communication_device;
        hdr->classcode[1] = Pci_class_code_other_device;
        break;
      case L4VIRTIO_ID_INPUT:
        hdr->classcode[2] = Pci_class_code_input_device; // Input devices
        hdr->classcode[1] = Pci_class_code_other_device; // Other input controller
        break;
      default:
        hdr->classcode[2] = Pci_class_code_unknown_device;
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
  create_vio_pci_cap_common_entry(Virtio_pci_cap *prev, unsigned bar_idx)
  {
    auto *entry   = create_pci_cap<Virtio_pci_common_cap>();
    entry->bar    = bar_idx;
    // Start the BAR with the PCI common config
    entry->offset = prev ? prev->offset + prev->length : 0;
    entry->length = sizeof(Virtio_pci_common_cfg);

    return entry;
  }

  Virtio_pci_cap *
  create_vio_pci_cap_notify_entry(Virtio_pci_cap *prev, unsigned bar_idx)
  {
    auto *entry   = create_pci_cap<Virtio_pci_notify_cap>();
    entry->bar    = bar_idx;
    // offset must be 2 byte aligned
    entry->offset = prev ? l4_round_size(prev->offset + prev->length, 1) : 0;
    entry->length = 2; // smallest possible length

    entry->notify_off_multiplier = 0;

    return entry;
  }

  Virtio_pci_cap *create_vio_pci_cap_isr_entry(Virtio_pci_cap *prev,
                                               unsigned bar_idx)
  {
    auto *entry   = create_pci_cap<Virtio_pci_isr_cap>();
    entry->bar    = bar_idx;
    entry->offset = prev ? prev->offset + prev->length : 0;
    entry->length = 2;

    return entry;
  }

  /// The device cap uses the rest of the BAR. Must be the last cap created.
  Virtio_pci_cap *create_vio_pci_cap_device_entry(Virtio_pci_cap *prev,
                                                  unsigned bar_idx)
  {
    // 4 byte align offset to find device specific config
    unsigned entry_start =
      prev ? l4_round_size(prev->offset + prev->length, 2) : 0;

    if (entry_start >= bars[bar_idx].size)
      return nullptr;

    auto *entry   = create_pci_cap<Virtio_pci_device_cap>();
    entry->bar    = bar_idx;
    entry->offset = entry_start;
    entry->length = bars[bar_idx].size - entry_start;

    // limit the size of this entry to something sensible. IO BARs are not that
    // large, but MMIO BARs tend to be 4K, which is way too much for the VirtIO
    // device config.
    if (entry->length > 0x200)
      entry->length = 0x200;

    return entry;
  }

  Virtio_pci_cap *create_vio_pci_cap_pci_entry(Virtio_pci_cap *prev,
                                               unsigned bar_idx)
  {
    auto *entry   = create_pci_cap<Virtio_pci_cfg_cap>();
    entry->bar    = bar_idx;
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
   *
   * \pre The BAR starts with the MSI-X table at offset 0 and PBA right behind
   *      it.
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

    trace().printf("msi.msg_ctrl 0x%x\n", cap->ctrl.raw);
    trace().printf("msi.table 0x%x\n", cap->tbl.raw);
    trace().printf("msi.pba 0x%x\n", cap->pba.raw);
    trace().printf("Size of MSI-X cap 0x%lx\n", sizeof(*cap));
  }

  inline void
  check_msix_bar_constraints(unsigned msix_idx)
  {
    if (msix_idx == -1U)
      L4Re::throw_error(-L4_EINVAL,
                        "Configure the device with an MMIO BAR for the MSI-X table.");

    if (bars[msix_idx].size < Msix_mem_need)
      {
        Err().printf("At least 0x%x Bytes of MSI-X memory are configured in BAR %u.\n",
                     Msix_mem_need, msix_idx);
        L4Re::throw_error(-L4_EINVAL, "More MSI-X memory necessary.");
      }
  }

  inline void
  check_config_space_constraints(unsigned bar_idx, bool mmio_bar)
  {
    if (bar_idx == -1U)
      L4Re::throw_error(
        -L4_EINVAL,
        "Configure the device with an IO or MMIO32 BAR for the VirtIO device interface.");

    if (mmio_bar)
      {
        if (bars[bar_idx].size < L4_PAGESIZE)
          {
            Err().printf("Configure at least a size of 4KB for the MMIO32 BAR %u.\n",
                         bar_idx);
            L4Re::throw_error(-L4_EINVAL,
                              "VirtIO device config space must have a size of 4KB or more.");
          }
      }
    else
      {
        if (bars[bar_idx].size < Num_pci_connector_ports)
          {
            Err().printf("Configured IO ports in BAR %u are a power of 2 >= 0x%x.\n",
                         bar_idx, Num_pci_connector_ports);
            L4Re::throw_error(-L4_EINVAL, "More IO ports necessary.");
          }
      }
  }

  /**
   * Per convention we return the first MMIO32 BAR fitting an MSI-X table.
   */
  unsigned msix_bar_idx() const
  {
    for (unsigned i = 0; i < Bar_num_max_type0; ++i)
      if (bars[i].type == Pci_cfg_bar::MMIO32 && bars[i].size >= Msix_mem_need)
        return i;

    return -1;
  }

  /**
   * Per convention we return the first BAR that fits `type`. The first MMIO32
   * BAR is skipped, as it is solely used for the MSI-X table.
   */
  unsigned virtio_bar_idx(Pci_cfg_bar::Type type) const
  {
    // The first MMIO32 BAR is for the MSI-X table, thus skip it.
    bool skip_next_mmio32 = type == Pci_cfg_bar::MMIO32;
    for (unsigned i = 0; i < Bar_num_max_type0; ++i)
      if (bars[i].type == type)
        {
          if (skip_next_mmio32)
            skip_next_mmio32 = false;
          else
            return i;
        }

    return -1;
  }

  DEV *dev() { return static_cast<DEV *>(this); }
  DEV const *dev() const { return static_cast<DEV const *>(this); }
}; // class Virtio_device_pci


} } // namespace Vdev::Pci
