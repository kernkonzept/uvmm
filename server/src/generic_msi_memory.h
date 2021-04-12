/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <mutex>

#include <l4/cxx/unique_ptr>
#include <l4/re/util/object_registry>

#include "debug.h"
#include "mem_access.h"
#include "pci_device.h"
#include "msi.h"
#include "msi_allocator.h"
#include "ds_mmio_handling.h"
#include "msi_controller.h"

namespace Vdev { namespace Msix {

/**
 * Translates the L4Re interrupt to the MSIx Table entry and send it to
 * the Msix_controller.
 */
class Msi_src
: public L4::Irqep_t<Msi_src>,
  public virtual Vdev::Dev_ref
{
public:
  explicit Msi_src(Table_entry const *entry,
                   cxx::Ref_ptr<Gic::Msix_controller> const &ctrl,
                   l4_uint32_t io_irq)
  : _entry(entry), _msix_ctrl(ctrl), _io_irq(io_irq)
  {}

  void handle_irq() const
  { _msix_ctrl->send(_entry->addr, _entry->data); }

  l4_uint32_t io_irq() const
  { return _io_irq; }

private:
  Table_entry const *_entry;
  cxx::Ref_ptr<Gic::Msix_controller> const _msix_ctrl;
  l4_uint32_t const _io_irq;
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
                  L4Re::Util::Object_registry *registry,
                  l4_uint64_t src_id,
                  unsigned num_entries,
                  cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl)
  : _con(std::move(con)),
    _registry(registry),
    _msi_alloc(msi_alloc),
    _msi_irqs(num_entries),
    _src_id(src_id),
    _msix_ctrl(msix_ctrl),
    _virt_table(cxx::make_unique<Table_entry[]>(num_entries))
  {
    unsigned icu_nr_msis = msi_alloc->max_msis();
    if (num_entries > icu_nr_msis)
      {
        Err().printf("ICU does not support enough MSIs. Requested %i; "
                     "Supported %i\n",
                     num_entries, icu_nr_msis);
        L4Re::chksys(-L4_EINVAL, "Configure more MSIs for the vBus ICU.");
      }
  }

  ~Virt_msix_table()
  {
    for (auto &msi : _msi_irqs)
      if (msi != nullptr)
        {
          _msi_alloc->icu()->unbind(msi->io_irq() | L4_ICU_FLAG_MSI,
                                    msi->obj_cap());
          _msi_alloc->free_msi(msi->io_irq());
          _registry->unregister_obj(msi.get());
        }
  }

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
    warn().printf("PASS_THROUGH_MEM: write @ 0x%x (0x%x): 0x%lx\n",
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

    warn().printf("%s MSI-X entry %u\n", mask ? "masking" : "unmasking", idx);

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
    warn().printf("reconfiguring\n");
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
    // guard against multiple threads accessing the Msi_allocator and the
    // capability allocator
    std::lock_guard<std::mutex> lock(_mutex);

    Table_entry const *entry = &_virt_table[idx];

    warn().printf("Configure MSI-X entry number %u for entry (0x%llx, 0x%x)\n",
                  idx, entry->addr, entry->data);

    // Allocate the number with the vBus ICU
    long msi =
      L4Re::chksys(_msi_alloc->alloc_msi(), "MSI-X vector allocation failed.");

    // allocate IRQ object and bind it to the ICU
    auto msi_src = Vdev::make_device<Msi_src>(entry, _msix_ctrl, msi);
    _registry->register_irq_obj(msi_src.get());

    long label = L4Re::chksys(_msi_alloc->icu()->bind(msi | L4_ICU_FLAG_MSI,
                                                      msi_src->obj_cap()),
                              "Bind MSI-IRQ to vBUS ICU.");

    // Currently, this doesn't happen for MSIs as IO's ICU doesn't manage them.
    // VMM Failure is not an option, as this is called during guest runtime.
    // What would be the graceful case?
    if (label > 0)
      warn().printf("ICU bind returned %li. Unexpected unmask via vBus ICU "
                    "necessary.\n", label);

    // get MSI info
    l4_icu_msi_info_t msiinfo;
    L4Re::chksys(_msi_alloc->icu()->msi_info(msi | L4_ICU_FLAG_MSI, _src_id,
                                             &msiinfo),
                 "Acquire MSI entry from vBus.");

    warn().printf("msi address: 0x%llx, data 0x%x\n", msiinfo.msi_addr,
                  msiinfo.msi_data);

    // write to device memory
    write_dev_msix_entry(idx, msiinfo);

    // unmask the MSI-IRQ
    L4Re::chkipc(msi_src->obj_cap()->unmask(), "Unmask MSI-IRQ.");
    _msi_irqs[idx] = msi_src;
  }

  cxx::Ref_ptr<Vdev::Mmio_ds_converter> _con;
  L4Re::Util::Object_registry *_registry;
  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  std::vector<cxx::Ref_ptr<Msi_src>> _msi_irqs;
  l4_uint64_t const _src_id;
  cxx::Ref_ptr<Gic::Msix_controller> _msix_ctrl;
  cxx::unique_ptr<Table_entry[]> _virt_table;
  std::mutex _mutex;
}; // class Virt_msix_table

} } // namespace Vdev::Msix
