/*
 * Copyright (C) 2019-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <mutex>

#include <l4/cxx/unique_ptr>

#include "debug.h"
#include "vcpu_obj_registry.h"
#include "mem_access.h"
#include "pci_device.h"
#include "msix.h"
#include "msi_allocator.h"
#include "ds_mmio_handling.h"
#include "msi_controller.h"
#include "msi_irq_src.h"

namespace Vdev { namespace Msix {

/**
 * Translates the L4Re interrupt to the MSIx Table entry and send it to
 * the Msix_controller.
 */
class Msix_src
: public Msi_irq_src<Msix_src>,
  public virtual Vdev::Dev_ref
{
public:
  explicit Msix_src(cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
                    Gic::Msix_dest const &msix_dest,
                    Vcpu_obj_registry *registry,
                    Table_entry const *entry)
  : Msi_irq_src<Msix_src>(msi_alloc, msix_dest, registry), _entry(entry)
  {}

  l4_uint64_t msi_vec_addr() const
  { return _entry->addr; }

  l4_uint64_t msi_vec_data() const
  { return _entry->data; }

private:
  Table_entry const *_entry;
};

/**
 * MSI-X table emulation.
 *
 * The guest accesses this emulation, when reading from or writing to
 * the device's MSI-X table. If the guest unmasks an MSI-X entry, this
 * emulation configures the MSI routing from the device to the VMM and to
 * the guest.
 */
class Virt_msix_table : public Vmm::Mmio_device_t<Virt_msix_table>
{
public:
  /**
   * Create a MMIO memory handler for MSI-X table memory.
   *
   * \param con          Access to physical device memory.
   * \param msi_alloc    Pointer to a MSI manager, e.g. vBus.
   * \param registry     Application-global object registry.
   * \param src_id       IO-specific source ID of the PCI device.
   * \param num_entries  Maximum number of device-supported MSI-X entries.
   * \param msix_ctrl    MSI-X controller for MSI-X address decoding.
   */
  Virt_msix_table(cxx::Ref_ptr<Vdev::Mmio_ds_converter> &&con,
                  cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
                  Vcpu_obj_registry *registry,
                  l4_uint64_t src_id,
                  unsigned num_entries,
                  Gic::Msix_dest const &msix_dest)
  : _con(std::move(con)),
    _registry(registry),
    _msi_alloc(msi_alloc),
    _msi_irqs(num_entries),
    _src_id(src_id),
    _msix_dest(msix_dest),
    _virt_table(cxx::make_unique<Table_entry[]>(num_entries))
  {}

  /// Read from the emulated MSI-X memory.
  l4_umword_t read(unsigned reg, char size, unsigned) const
  {
    // In case of the vector control, we need to ensure earlier writes reached
    // the device, hence, we read.
    if (is_entry_control(reg, size))
      _con->read(reg, size);

    return Vmm::Mem_access::read_width(
             reinterpret_cast<l4_addr_t>(_virt_table.get()) + reg, size);
  }
  /// Write to the emulated MSI-X memory.
  void write(unsigned reg, char size, l4_umword_t value, unsigned)
  {
    trace().printf("PASS_THROUGH_MEM: write @ 0x%x (0x%x): 0x%lx\n",
                   reg, size, value);

    Vmm::Mem_access::write_width(
      reinterpret_cast<l4_addr_t>(_virt_table.get()) + reg, value, size);

    // Handle MSI-X table access
    if (is_entry_unmask(reg, size, value))
      conf_msix_entry(reg_to_entry(reg));
    else if (is_entry_mask(reg, size, value))
      msi_entry_mask_ctrl(reg_to_entry(reg), true);
    // else: PCIe brings TPH Requester fields for vector control.
  }

  char const *dev_name() const override { return "Virt_msix_table"; }

protected:
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PassThrough"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PassThrough"); }

private:
  /// MSI-X table access to the vector control DWORD.
  static bool is_entry_control(unsigned reg, char size)
  {
    enum { Entry_ctrl_offset = 12 };

    return    ((reg % Entry_size) == Entry_ctrl_offset)
           && (size == Vmm::Mem_access::Wd32);
  }

  /// Access clears the mask bit in the vector control.
  static bool is_entry_unmask(unsigned reg, char size, l4_umword_t value)
  {
    return    is_entry_control(reg, size)
           && (value & Vector_ctrl_mask_bit) == 0;
  }

  /// Access sets the mask bit in the vector control.
  static bool is_entry_mask(unsigned reg, char size, l4_umword_t value)
  {
    return    is_entry_control(reg, size)
           && (value & Vector_ctrl_mask_bit);
  }

  /// Convert the register access to the entry number.
  static unsigned reg_to_entry(unsigned reg)
  {
    return reg / Entry_size;
  }

  /// Mask MSI-X entry on device.
  void msi_entry_mask_ctrl(unsigned idx, bool mask) const
  {
    enum { Vector_offset = 12 };

    trace().printf("%s MSI-X entry %u\n", mask ? "masking" : "unmasking", idx);

    unsigned reg = idx * Entry_size + Vector_offset;
    l4_umword_t val = _con->read(reg, Vmm::Mem_access::Wd32);

    if (mask)
      val |= Vector_ctrl_mask_bit;
    else
      val &= ~Vector_ctrl_mask_bit;

    _con->write(reg, Vmm::Mem_access::Wd32, val);
  }

  /// Write device's MSI-X entry.
  void write_dev_msix_entry(unsigned idx, l4_icu_msi_info_t const &info) const
  {
    unsigned entry_off = idx * Entry_size;
    unsigned width = 1U << Vmm::Mem_access::Wd32;

    _con->write(entry_off, Vmm::Mem_access::Wd32, info.msi_addr & 0xffffffffU);

    entry_off += width;
    _con->write(entry_off, Vmm::Mem_access::Wd32, info.msi_addr >> 32);

    entry_off += width;
    _con->write(entry_off, Vmm::Mem_access::Wd32, info.msi_data);

    entry_off += width;
    _con->write(entry_off, Vmm::Mem_access::Wd32, 0U);
  }

  /// True; iff the MSI route was already configured, but masked.
  bool reconfigure(unsigned idx) const
  {
    // Check for reconfiguration or entry unmask
    trace().printf("check for reconfiguration\n");

    if (!_msi_irqs[idx])
      return false;

    // If the entry is present, we just unmask the entry on the device.
    trace().printf("reconfiguring\n");
    msi_entry_mask_ctrl(idx, false);

    return true;
  }

  /// Parse MSI-X entry and configure the route.
  void conf_msix_entry(unsigned idx)
  {
    // If this is a reconfiguration do not configure the device again.
    if (!reconfigure(idx))
      configure_msix_route(idx);
  }

  /**
   * Configure the device's MSI-X entry and the interrupt route to inject into
   * the guest.
   */
  void configure_msix_route(unsigned idx)
  {
    if (!_msix_dest.is_present())
      {
        warn().printf("No MSI-X controller! Entry %u not routed to guest.\n",
                      idx);
        return;
      }

    // guard against multiple threads accessing the Msi_allocator and the
    // capability allocator
    std::lock_guard<std::mutex> lock(_mutex);

    Table_entry const *entry = &_virt_table[idx];

    trace().printf("Configure MSI-X entry number %u for entry (0x%llx, 0x%x)\n",
                   idx, entry->addr, entry->data);

    // allocate IRQ object and bind it to the ICU
    auto msi_src = Vdev::make_device<Msix_src>(_msi_alloc, _msix_dest,
                                               _registry, entry);

    // get MSI info
    l4_icu_msi_info_t msiinfo;
    msi_src->msi_info(_src_id, &msiinfo);

    // write to device memory
    write_dev_msix_entry(idx, msiinfo);

    // unmask the MSI-IRQ
    L4Re::chkipc(msi_src->obj_cap()->unmask(), "Unmask MSI-IRQ.");
    _msi_irqs[idx] = msi_src;
  }

  cxx::Ref_ptr<Vdev::Mmio_ds_converter> _con;
  Vcpu_obj_registry *_registry;
  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  std::vector<cxx::Ref_ptr<Msix_src>> _msi_irqs;
  l4_uint64_t const _src_id;
  Gic::Msix_dest _msix_dest;
  cxx::unique_ptr<Table_entry[]> _virt_table;
  std::mutex _mutex;
}; // class Virt_msix_table

} } // namespace Vdev::Msix
