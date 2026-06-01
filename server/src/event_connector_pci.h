/*
 * Copyright (C) 2017-2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/re/util/unique_cap>

#include "pci_device.h"
#include "msi_controller.h"
#include "msix.h"
#include "virtio_event_connector.h"
#include "mmio_device.h"
#include "ds_manager.h"
#include "guest.h"

namespace Virtio {

/**
 * This MSI-X connector supports sending MSIs configured in the MSI-X table.
 *
 * For further documentation look at Event_connector_irq.
 */
class Event_connector_msix
{
  class Msix_table_pba_mem : public Vmm::Ro_ds_mapper_t<Msix_table_pba_mem>
  {
  public:
    /**
     * Read-only MMIO device managing the continuous virtual MSI-X memory area.
     *
     * \param num_msix_entries   Number of entries the MSI-X table must contain.
     * \param msix_table_offset  Offset of the MSI-X table within the memory
     *                           area.
     * \param msix_pba_offset    Offset of the pending-bit array within the
     *                           memory area.
     * \param evcon              Object to send pending events to on unmask.
     */
    explicit Msix_table_pba_mem(unsigned num_msix_entries,
                                l4_size_t msix_table_offset,
                                l4_size_t msix_pba_offset,
                                Event_connector_msix *evcon)
    : _evcon(evcon),
      _num_msix_entries(num_msix_entries),
      _msix_table_offset(msix_table_offset),
      _pba_offset(msix_pba_offset)
    {
      l4_size_t size = Vdev::Msix::msix_table_pba_mem_size(num_msix_entries);
      auto *e = L4Re::Env::env();

      _ds = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
                         "Failed to allocate dataspace capability for MSI-X table and PBA.");

      L4Re::chksys(e->mem_alloc()->alloc(size, _ds.get(),
                                         L4Re::Mem_alloc::Continuous),
                   "Failed to allocate continuous memory for MSI-X table and PBA.");
      _mgr = cxx::make_unique<Vmm::Ds_manager>("MSI-X-PBA", _ds.get(), 0, size,
                                               L4Re::Rm::F::Cache_uncached
                                                 | L4Re::Rm::F::RW);
      _mgr->local_addr<void *>();
      _pba = cxx::make_unique<
        Vdev::Msix::Pending_bit_array>(_mgr->local_addr<l4_addr_t>()
                                         + _pba_offset,
                                       num_msix_entries);
    }

    l4_size_t mapped_mmio_size() const { return _mgr->size(); }

    L4::Cap<L4Re::Dataspace> mmio_ds() const
    { return _mgr->dataspace(); }

    l4_addr_t *mmio_local_addr() const
    { return _mgr->local_addr<l4_addr_t *>(); }

    /**
     * Handle writes to the MSI-X memory area.
     */
    void write(unsigned reg, char size, l4_umword_t value, unsigned /*cpu_id*/)
    {
      if (size != Vmm::Mem_access::Width::Wd32)
        {
          info().printf("Only 32-bit wide access supported. Ignoring write to "
                        "0x%x/%u value 0x%lx.\n",
                        reg, 8 << size, value);
          return;
        }

      if (   reg < _msix_table_offset
          || reg > _pba_offset + Vdev::Msix::Pending_bit_array::Max_size)
        {
          info().printf("Access outside emulated MSI-X table & PBA area. "
                        "Ignoring write to 0x%x/%u value 0x%lx.\n",
                        reg, 8 << size, value);
          return;
        }

      if (reg >= _msix_table_offset && reg < _pba_offset)
        write_msix_table(reg - _msix_table_offset, size, value);
      else
        _pba->write(reg - _pba_offset, size, value);
    };

    Vdev::Msix::Pending_bit_array *pba() const
    { return _pba.get(); }

    Vdev::Msix::Table_entry *table_entry(unsigned idx) const
    { return &(_mgr->local_addr<Vdev::Msix::Table_entry *>()[idx]); }

  private:
    static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "vMSI-X Mem"); }

    char const *dev_name() const override { return _mgr->dev_name(); }

    /**
     * Handle DWORD-aligned write to the MSI-X table. Drops unaligned and
     * out-of-bounds writes.
     */
    void write_msix_table(unsigned reg, char /*size*/, l4_umword_t value)
    {
      unsigned idx = reg / Vdev::Msix::Table_entry_const::Entry_size;
      if (idx >= _num_msix_entries)
        {
          info()
            .printf("Ignoring out-of-bounds write @ %u: entry #%i,"
                    " table size %u.\n", reg, idx, _num_msix_entries);
          return;
        }

      Vdev::Msix::Table_entry *entry = table_entry(idx);

      switch (reg % 16) // Dword-aligned access
        {
        case Vdev::Msix::Offset_addr_low:
          entry->addr = (entry->addr & 0xffff'ffff'0000'0000ULL)
                        | static_cast<l4_uint64_t>(value);
          break;
        case Vdev::Msix::Offset_addr_high:
          entry->addr = (entry->addr & 0x0000'0000'ffff'ffffULL)
                        | static_cast<l4_uint64_t>(value) << 32;
          break;
        case Vdev::Msix::Offset_data:
          entry->data = value;
          break;
        case Vdev::Msix::Offset_ctrl:
          {
            bool was_masked = entry->masked();
            entry->vector_ctrl = value;

            if (was_masked && !entry->masked())
              if (_pba->is_set(idx))
                {
                  _evcon->send_event(idx);
                  _pba->clear(idx);
                }
            break;
          }
        default:
          info().printf("Ignoring unaligned access: 0x%x to table entry %u.\n",
                         reg, idx);
        }
    }

    Event_connector_msix *_evcon;
    unsigned _num_msix_entries;
    l4_size_t _msix_table_offset;
    l4_size_t _pba_offset;
    L4Re::Util::Unique_cap<L4Re::Dataspace> _ds;
    cxx::unique_ptr<Vmm::Ds_manager> _mgr;
    cxx::unique_ptr<Vdev::Msix::Pending_bit_array> _pba;
  }; // class Msix_table_pba_mem

public:
  Event_connector_msix(unsigned max_msix_entries, l4_size_t msix_table_offset,
                       l4_size_t msix_pba_offset,
                       Gic::Msix_dest const &msix_dest)
  : _msix_dest(msix_dest),
    _msix_mem(cxx::make_ref_obj<Msix_table_pba_mem>(max_msix_entries,
                                                    msix_table_offset,
                                                    msix_pba_offset, this))
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
    if (entry->masked())
      pba()->set(idx);
    else
      _msix_dest.send_msix(entry->addr, entry->data);
  }

  void clear_events(unsigned) {}

  l4_size_t mem_size() const
  { return _msix_mem->mapped_mmio_size(); }

  /// MSI-X memory handling guest access.
  cxx::Ref_ptr<Vmm::Mmio_device> mmio_device() const
  { return _msix_mem; }

private:
  Gic::Msix_dest _msix_dest;
  cxx::Ref_ptr<Msix_table_pba_mem> _msix_mem;

  Vdev::Msix::Pending_bit_array *pba() const { return _msix_mem->pba(); }

  Vdev::Msix::Table_entry *msix_entry(l4_uint16_t idx) const
  {
    return _msix_mem->table_entry(idx);
  }

}; // class Event_connector_msix

} // namespace Virtio
