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

enum
{
  Dt_pci_flags_io = 1 << 24,
  Dt_pci_flags_mmio32 = 1 << 25,
  Dt_pci_flags_mmio64 = 3 << 25,
  Dt_pci_flags_prefetch = 1 << 30,
};

struct Device_register_entry
{
  l4_uint64_t base;
  l4_uint64_t size;
  l4_uint32_t flags;

  void print() const
  {
    Dbg().printf("base 0x%llx, size 0x%llx, flags 0x%x\n", base, size, flags);
  }
};

/**
 * Virtio device using the Virtio PCI transport employing MSI-X.
 */
template<typename DEV>
class Virtio_device_pci
: public Virt_pci_device
{
public:
  /**
   * Late configuration to allow Virtio_proxy to connect to l4virtio device
   * first. Call this after register_irq().
   *
   * \param regs              Array of BAR entries.
   * \param regs_size         Array size.
   * \param num_msix_entries  Maximum number of MSI-X entries to handle.
   * \param dev_cfg_size      Size of the device-specific configuration space.
   */
  void configure(cxx::static_vector<Device_register_entry> const &regs,
                 unsigned num_msix_entries, unsigned dev_cfg_size = 0)
  {
    config_device(regs, num_msix_entries, dev_cfg_size);
    dbg().printf("Virtio_device_pci: device configured\n");
  }

  bool msix_enabled()
  {
    parse_msix_cap();
    return has_msix? msix_cap.ctrl.enabled() : false;
  }

private:
  void set_space(unsigned bar, l4_uint32_t value, l4_size_t sz, bool io)
  {
    io ? set_io_space<Pci_header::Type0>(bar, value, sz)
       : set_mem_space<Pci_header::Type0>(bar, value, sz);
  }

  void config_device(cxx::static_vector<Device_register_entry> const &regs,
                     unsigned num_msix_entries,
                     unsigned dev_cfg_size)
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

    Virtio_pci_cap *cap = create_vio_pci_cap_common_entry(nullptr, io_bar);
    cap = create_vio_pci_cap_notify_entry(cap, io_bar);
    cap = create_vio_pci_cap_isr_entry(cap, io_bar);
    cap = create_vio_pci_cap_pci_entry(cap, io_bar);

    // Must be the last cap created!
    if (dev_cfg_size)
      cap = create_vio_pci_cap_device_entry(cap, io_bar, dev_cfg_size);

    // Check actual I/O BAR usage vs configured I/O BAR size
    l4_uint32_t bar_length = cap->offset + cap->length;

    if (bar_length > regs[io_bar].size)
      {
        Err().printf("Actual size greater configured size due to alignment: "
                     "0x%x > 0x%llx\n",
                     bar_length, regs[io_bar].size);
        L4Re::chksys(-L4_EINVAL, "Configure greater I/O bar size.");
      }
  }

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
                                                  unsigned io_bar,
                                                  unsigned cfgsz)
  {
    auto *entry   = create_pci_cap<Virtio_pci_device_cap>();
    entry->bar    = io_bar;
    // 4 byte align offset to find device specific config
    entry->offset = prev ? l4_round_size(prev->offset + prev->length, 2) : 0;

    unsigned entry_end = entry->offset + cfgsz;
    // 0x100 is the maximum length of the IO BAR.
    if (entry_end > 0x100)
      {
        // reduce cfg size due to alignment constraints
        unsigned overflow = entry_end - 0x100U;
        cfgsz -= overflow;

        dbg().printf("WARNING: device config space truncated by %i bytes: "
                     "offset 0x%x, length 0x%x\n",
                     overflow, entry->offset, cfgsz);
      }

    entry->length = cfgsz;

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

  DEV *dev() { return static_cast<DEV *>(this); }
  DEV const *dev() const { return static_cast<DEV const *>(this); }
}; // class Virtio_device_pci


inline void
check_power_of_2(l4_uint64_t size, char const *err)
{
  if (size & (size - 1))
    L4Re::chksys(-L4_EINVAL, err);
}

inline void
check_dt_io_mmio_constraints(l4_uint64_t msi_base, l4_uint64_t msi_size,
                             l4_uint64_t port_base, l4_uint64_t port_size)
{
  check_power_of_2(msi_size, "MSI-X memory size must be a power of 2.");
  check_power_of_2(port_size, "I/O space size must be a power of 2.");

  // PCI BARs handle 32bit addresses only.
  if (((port_base >> 32) != 0) && ((port_size >> 32) != 0)
      && ((msi_base >> 32) != 0))
    L4Re::chksys(-L4_EINVAL, "Device memory is below 4GB.");

  if (msi_size < Msix_mem_need)
    {
      Err().printf("At least 0x%x Bytes of MSI-X memory are configured.\n",
                   Msix_mem_need);
      L4Re::chksys(-L4_EINVAL, "More MSI-X memory necessary.");
    }

  if (port_size < Num_pci_connector_ports)
    {
      Err().printf("Configured IO ports are a power of 2 >= 0x%x.\n",
                   Num_pci_connector_ports);
      L4Re::chksys(-L4_EINVAL, "More IO ports necessary.");
    }

  if (port_size > 0x100)
    L4Re::chksys(-L4_EINVAL, "Device IO port configuration sizes up to 0x100 "
                             "supported.");
}

inline void
check_dt_regs_flag(cxx::static_vector<Device_register_entry> const &regs)
{
  if (!(regs[0].flags & Dt_pci_flags_mmio32))
    L4Re::chksys(-L4_EINVAL, "First DT register entry is a MMIO(32) entry.");

  if (!(regs[1].flags & Dt_pci_flags_io))
    L4Re::chksys(-L4_EINVAL, "Second DT register entry is an IO entry.");
}

} } // namespace Vdev::Pci
