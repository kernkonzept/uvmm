/*
 * Copyright (C) 2019-2020 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/env>
#include <l4/re/rm>
#include <l4/re/dataspace>
#include <l4/re/error_helper>
#include <l4/cxx/ref_ptr>

#include "debug.h"
#include "device.h"
#include "mem_access.h"

namespace Vdev {

/**
 * Manager to multiplex access to a specific dataspace.
 *
 * When using this class in cooperation with Ds_mmio_converter you have to
 * ensure that the accessed areas do not overlap and the accesses are within
 * the managed dataspace.
 */
class Ds_access_mgr : public cxx::Ref_obj
{
public:
  /**
   * Map and manage `size` bytes of MMIO memory starting at `start`.
   *
   * \param ds         Dataspace containing the area to map and manage.
   * \param start      Start of the area.
   * \param size       Size of the area.
   * \param add_flags  Additional flags to use when attaching the dataspace.
   *                   Search_addr, Eager_map, RW are always applied.
   */
  explicit Ds_access_mgr(L4::Cap<L4Re::Dataspace> ds,
                         l4_addr_t start,
                         unsigned size,
                         L4Re::Rm::Flags add_flags = L4Re::Rm::F::Cache_uncached)
  : _mem(attach_memory(ds, start, size, add_flags))
  {}

  /**
   * Read from device memory.
   *
   * \param offset  Offset into the managed memory region to read from.
   * \param size    Width of the read access.
   *
   * \return  Read result.
   *
   * \pre The read access must be within the managed area.
   */
  l4_umword_t read(unsigned offset, char size) const
  { return Vmm::Mem_access::read_width(_mem.get() + offset, size); }

  /**
   * Write to device memory.
   *
   * \param offset  Offset into the managed memory region to write to.
   * \param size    Width of the write access.
   *
   * \pre The write access must be within the managed area.
   */
  void write(unsigned offset, char size, l4_umword_t value) const
  { Vmm::Mem_access::write_width(_mem.get() + offset, value, size); }

private:
  /// Attach the device memory to the local address space.
  static L4Re::Rm::Unique_region<l4_addr_t>
  attach_memory(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                l4_size_t size, L4Re::Rm::Flags add_flags)
  {
    L4Re::Rm::Flags rm_flags = L4Re::Rm::F::Search_addr | L4Re::Rm::F::Eager_map
                               | L4Re::Rm::F::RW | add_flags;
    auto rm = L4Re::Env::env()->rm();
    size = l4_round_page(size);
    offset = l4_trunc_page(offset);

    L4Re::Rm::Unique_region<l4_addr_t> mem;
    L4Re::chksys(rm->attach(&mem, size, rm_flags, ds, offset),
                 "Attach memory.");

    info().printf("Attached memory [0x%lx, 0x%lx] to 0x%lx\n", offset,
                  offset + size - 1, mem.get());

    return cxx::move(mem);
  }

  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "DsAccMgr"); }

  /// Device memory region
  L4Re::Rm::Unique_region<l4_addr_t> _mem;
}; // class Ds_access_mgr

/**
 * Convert MMIO accesses to the Ds_access_mgr interface and manage the offset
 * into the managed area.
 */
class Mmio_ds_converter : public Vmm::Mmio_device_t<Mmio_ds_converter>
{
public:
  /**
   * Connector to the manager of the device memory region.
   *
   * \param mgr     Manager of device memory.
   * \param offset  Memory offset into the memory managed by `mgr`.
   */
  Mmio_ds_converter(cxx::Ref_ptr<Ds_access_mgr> mgr, l4_addr_t offset)
  : _mem_mgr(mgr), _offset(offset)
  {}

  /// Apply local offset to `reg` and read from device memory.
  l4_umword_t read(unsigned reg, char size, unsigned = 0) const
  { return _mem_mgr->read(_offset + reg, size); }

  /// Apply local offset to `reg` and write to device memory.
  void write(unsigned reg, char size, l4_umword_t value, unsigned = 0) const
  { _mem_mgr->write(_offset + reg, size, value); }

  char const *dev_name() const override { return "Mmio_ds_converter"; }

private:
  /// MMIO memory region manager.
  cxx::Ref_ptr<Ds_access_mgr> _mem_mgr;
  /// Offset inside the Dev_ds_manager memory region.
  l4_addr_t _offset;
}; // class Mmio_ds_converter

} // namespace Vdev
