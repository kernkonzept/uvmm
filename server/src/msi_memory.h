/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/env>
#include <l4/re/rm>
#include <l4/cxx/utils>
#include <l4/cxx/unique_ptr>
#include <l4/re/util/unique_cap>
#include <l4/re/util/object_registry>

#include "debug.h"
#include "mem_types.h"
#include "mem_access.h"
#include "pci_device.h"
#include "virt_lapic.h"
#include "msi.h"
#include "msi_allocator.h"

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
 * MMIO memory handler for the MSI-X table memory of a PCI device.
 *
 * All accesses trap to the VMM. Reads and writes to memory outside the MSI-X
 * table is read/write-through. Inside the MSI-X table reads and writes go to
 * local memory, such that the device's MSI-X table is not touched by the guest
 * directly.
 */
class Table_memory
: public Vmm::Mmio_device_t<Table_memory>
{
  enum
  {
    Entry_ctrl_offset = 12,
  };

public:
  /**
   * Create a MMIO memory handler for MSI-X table memory.
   *
   * \param vbus_ds    Dataspace containing the device memory.
   * \param tbl        Address of the MSI-X table of the device.
   * \param msi_alloc  Pointer to a MSI manager, e.g. vBus.
   * \param registry   Application-global object registry.
   * \param max_num    Maximum number of device-supported MSI-X vectors.
   * \param src_id     IO-specific source ID of the PCI device.
   * \param apics      Local APICs for interrupt routing.
   */
  Table_memory(L4::Cap<L4Re::Dataspace> vbus_ds, l4_addr_t tbl,
               cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
               L4Re::Util::Object_registry *registry, unsigned max_num,
               unsigned src_id, cxx::Ref_ptr<Gic::Lapic_array> apics)
  : _dev_msix_tbl(attach_memory(vbus_ds, tbl, Entry_size * max_num,
                                L4Re::Rm::Cache_uncached)),
    _guest_msix_tbl(cxx::make_unique<Table_entry[]>(max_num)),
    _registry(registry),
    _msi_alloc(msi_alloc),
    _src_id(src_id),
    _guest_table(&_guest_msix_tbl[0], max_num),
    _dev_table(_dev_msix_tbl.get(), max_num),
    _local_apics(apics),
    _msi_irqs(max_num)
  {
    // This class assumes the table is at the beginning of the page;
    assert(tbl % L4_PAGESIZE == 0);

    unsigned icu_nr_msis = msi_alloc->max_msis();
    if (max_num >= icu_nr_msis)
      {
        Err().printf("ICU does not support enough MSIs. Requested %i; "
                     "Supported %i\n",
                     max_num, icu_nr_msis);
        L4Re::chksys(-L4_EINVAL, "Configure more MSIs for the vBus ICU.");
      }
  }

  ~Table_memory()
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

  l4_umword_t read(unsigned reg, char size, unsigned)
  {
    // if the read is within the MSI-X table, read local, else in device memory.
    l4_addr_t read_addr =
      (reg < (Entry_size * _msi_irqs.size()))
        ? _guest_table.start()
        : _dev_table.start();

    return Vmm::Mem_access::read_width(read_addr + reg, size);
  }

  void write(unsigned reg, char size, l4_umword_t value, unsigned)
  {
    warn().printf("PASS_THROUGH_MEM: write @ 0x%x (0x%x): 0x%lx\n", reg, size,
                  value);

    if (reg >= (Entry_size * _msi_irqs.size()))
      {
        // If the access is outside of the table, write to the actual device
        // memory.
        l4_addr_t dev_mem = _dev_table.start() + reg;
        Vmm::Mem_access::write_width(dev_mem, value, size);

        return;
      }

    l4_addr_t guest_mem = _guest_table.start() + reg;
    Vmm::Mem_access::write_width(guest_mem, value, size);

    // Handle MSI-X table access
    if (is_vector_unmask(reg, size, value))
      conf_msix_vector(reg_to_vector(reg));
    else if (is_vector_mask(reg, size, value))
      mask_msi_vector(reg_to_vector(reg));
    // else: PCIe brings TPH Requester fields for vector control.
  }

private:
  /// MSI-X table access to the vector control DWORD.
  bool is_vector_control(unsigned reg, char size) const
  {
    return    ((reg % Entry_size) == Entry_ctrl_offset)
           && (size == Vmm::Mem_access::Wd32);
  }

  /// Access clears the mask bit in the vector control.
  bool is_vector_unmask(unsigned reg, char size, l4_umword_t value) const
  {
    return    is_vector_control(reg, size)
           && (value & Vector_ctrl_mask_bit) == 0;
  }

  /// Access sets the mask bit in the vector control.
  bool is_vector_mask(unsigned reg, char size, l4_umword_t value) const
  {
    return    is_vector_control(reg, size)
           && (value & Vector_ctrl_mask_bit);
  }

  /// Convert the register access to the entry number.
  unsigned reg_to_vector(unsigned reg) const
  {
    return reg / Entry_size;
  }

  /// Mask MSI-X vector on device.
  void mask_msi_vector(unsigned tbl_idx)
  {
    warn().printf("masking MSI-X vector %u\n", tbl_idx);
    _dev_table.entry(tbl_idx).mask();
  }

  /// Convert the MSI's destination ID into an index in the local APIC array.
  unsigned msi_addr_to_lapic_idx(l4_uint64_t msi_addr) const
  {
    Interrupt_request_compat addr(msi_addr);
    auto lapic_id = addr.dest_id().get();

    int i = 0;
    while (lapic_id >>= 1)
      i++;

    warn().printf("msi destination id: 0x%x\n", i);
    return i;
  }

  /**
   * Configure the device's MSI-X entry and the interrupt route to inject into
   * the guest.
   */
  void conf_msix_vector(unsigned tbl_idx)
  {
    auto entry = _guest_table.entry(tbl_idx);
    auto guest_vector = entry.data & Data_vector_mask;

    warn().printf("Configure MSI-X vector number %u for guest vector 0x%x\n",
                  tbl_idx, guest_vector);

    Gic::Virt_lapic *lapic =
      _local_apics->get(msi_addr_to_lapic_idx(entry.addr)).get();

    // Check for reconfiguration or entry unmask
    trace().printf("check for reconfiguration\n");

    if (_msi_irqs[tbl_idx])
      {
        warn().printf("reconfiguring\n");
        auto msi_svr = _msi_irqs[tbl_idx];

        auto dev_entry = _dev_table.entry(tbl_idx);
        dev_entry.unmask();

        // If the Msi_svr is already present in the table, I assume the device
        // is already configured. I just have to inject the new vector at the
        // new destination.
        msi_svr->set_sink(lapic, guest_vector);

        return;
      }

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
    auto &dev_entry = _dev_table.entry(tbl_idx);
    dev_entry.addr = msiinfo.msi_addr;
    dev_entry.data = msiinfo.msi_data;
    dev_entry.unmask();

    // unmask the MSI-IRQ
    L4Re::chkipc(msi_svr->obj_cap()->unmask(), "Unmaks MSI-IRQ.");
    _msi_irqs[tbl_idx] = msi_svr;
  }

  /// Allocate a Dataspace for the guest's MSI-X table.
  static L4Re::Util::Unique_del_cap<L4Re::Dataspace>
  alloc_pagesize_ds()
  {
    auto ds = L4Re::chkcap(L4Re::Util::make_unique_del_cap<L4Re::Dataspace>());
    L4Re::chksys(L4Re::Env::env()->mem_alloc()->alloc(L4_PAGESIZE, ds.get()),
                 "Allocate a page of memory.");
    return cxx::move(ds);
  }

  /// Attach the device memory to the local address space.
  static L4Re::Rm::Unique_region<l4_umword_t>
  attach_memory(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                l4_size_t size, unsigned add_flags = 0)
  {
    unsigned rm_flags = L4Re::Rm::Search_addr | L4Re::Rm::Eager_map | add_flags;
    auto rm = L4Re::Env::env()->rm();
    size = l4_round_page(size);

    L4Re::Rm::Unique_region<l4_umword_t> mem;
    L4Re::chksys(rm->attach(&mem, size, rm_flags, ds, offset),
                 "Attach memory.");

    return cxx::move(mem);
  }

  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "PassThrough"); }
  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "PassThrough"); }

  L4Re::Rm::Unique_region<l4_umword_t> _dev_msix_tbl;
  cxx::unique_ptr<Table_entry[]> _guest_msix_tbl;
  L4Re::Util::Object_registry *_registry;
  cxx::Ref_ptr<Vdev::Msi::Allocator> _msi_alloc;
  unsigned const _src_id;
  Table _guest_table;
  Table _dev_table;
  cxx::Ref_ptr<Gic::Lapic_array> _local_apics;
  std::vector<cxx::Ref_ptr<Msi_svr>> _msi_irqs;
}; // class Table_memory

} } // namespace Vdev::Msix
