/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/unique_ptr>
#include <l4/re/util/object_registry>

#include "debug.h"
#include "mem_access.h"
#include "pci_device.h"
#include "virt_lapic.h"
#include "msi.h"
#include "msi_allocator.h"
#include "ds_mmio_handling.h"

namespace Vdev { namespace Msix {

/**
 * Forwards L4Re interrupts to an Irq_edge_sink containing the guest's
 * MSI/MSI-X vector.
 */
class Msi_svr
:  public L4::Irqep_t<Msi_svr>,
   public virtual Vdev::Dev_ref
{
public:
  Msi_svr(unsigned vbus_msi) : _io_msi(vbus_msi) {}

  void set_sink(Gic::Ic *ic, unsigned guest_msi)
  {
    _irq.rebind(ic, guest_msi);
    _guest_msi = guest_msi;
  }

  void handle_irq()
  {
    Dbg().printf("Msi_svr: injecting irq 0x%x\n", _guest_msi);
    _irq.inject();
  }

  unsigned io_irq() const
  { return _io_msi; }

private:
  Vmm::Irq_edge_sink _irq;
  unsigned _io_msi;
  unsigned _guest_msi;
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
   * \param apics        Local APICs for interrupt routing.
   * \param src_id       IO-specific source ID of the PCI device.
   * \param num_entries  Maximum number of device-supported MSI-X entries.
   */
  Virt_msix_table(cxx::Ref_ptr<Vdev::Mmio_ds_converter> &&con,
                  cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
                  L4Re::Util::Object_registry *registry,
                  cxx::Ref_ptr<Gic::Lapic_array> apics, unsigned src_id,
                  unsigned num_entries)
  : _con(std::move(con)),
    _registry(registry),
    _msi_alloc(msi_alloc),
    _local_apics(apics),
    _msi_irqs(num_entries),
    _src_id(src_id),
    _virt_table(cxx::make_unique<Table_entry[]>(num_entries))
  {
    unsigned icu_nr_msis = msi_alloc->max_msis();
    if (num_entries >= icu_nr_msis)
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

  /// Convert the MSI's destination ID into an index in the local APIC array.
  static unsigned msi_addr_to_lapic_idx(l4_uint64_t msi_addr)
  {
    Interrupt_request_compat addr(msi_addr);
    auto lapic_id = addr.dest_id().get();

    int i = 0;
    while (lapic_id >>= 1)
      i++;

    warn().printf("msi destination id: 0x%x\n", i);
    return i;
  }

  /// True; iff the MSI route was already configured, but masked.
  bool reconfigure(unsigned idx, unsigned guest_vector,
                   Gic::Virt_lapic *lapic) const
  {
    if (!_msi_irqs[idx])
      return false;

    warn().printf("reconfiguring\n");
    auto msi_svr = _msi_irqs[idx];
    msi_entry_mask_ctrl(idx, false);

    // If the Msi_svr is already present in the table, I assume the device
    // is already configured. I just have to inject the new vector at the
    // new destination.
    msi_svr->set_sink(lapic, guest_vector);

    return true;
  }

  /// Parse MSI-X entry and configure the route.
  void conf_msix_entry(unsigned idx)
  {
    Table_entry *entry = &_virt_table[idx];
    auto guest_vector = entry->data & Data_vector_mask;

    warn().printf("Configure MSI-X entry number %u for guest vector 0x%x\n",
                  idx, guest_vector);

    Gic::Virt_lapic *lapic =
      _local_apics->get(msi_addr_to_lapic_idx(entry->addr)).get();

    // Check for reconfiguration or entry unmask
    trace().printf("check for reconfiguration\n");

    // If this is a reconfiguration do not configure the device again.
    if (!reconfigure(idx, guest_vector, lapic))
      configure_msix_route(idx, guest_vector, lapic);
  }

  /**
   * Configure the device's MSI-X entry and the interrupt route to inject into
   * the guest.
   */
  void configure_msix_route(unsigned idx, unsigned guest_vector,
                            Gic::Virt_lapic *lapic)
  {
    // Allocate the number with the vBus ICU
    long msi =
      L4Re::chksys(_msi_alloc->alloc_msi(), "MSI-X vector allocation failed.");

    // allocate IRQ object and bind it to the ICU
    auto msi_svr = Vdev::make_device<Msi_svr>(msi);
    msi_svr->set_sink(lapic, guest_vector);
    _registry->register_irq_obj(msi_svr.get());

    long label = L4Re::chksys(_msi_alloc->icu()->bind(msi | L4_ICU_FLAG_MSI,
                                                      msi_svr->obj_cap()),
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
    L4Re::chkipc(msi_svr->obj_cap()->unmask(), "Unmaks MSI-IRQ.");
    _msi_irqs[idx] = msi_svr;
  }

  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PassThrough"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PassThrough"); }

  cxx::Ref_ptr<Vdev::Mmio_ds_converter> _con;
  L4Re::Util::Object_registry *_registry;
  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  cxx::Ref_ptr<Gic::Lapic_array> _local_apics;
  std::vector<cxx::Ref_ptr<Msi_svr>> _msi_irqs;
  unsigned const _src_id;
  cxx::unique_ptr<Table_entry[]> _virt_table;
}; // class Virt_msix_table

} } // namespace Vdev::Msix
