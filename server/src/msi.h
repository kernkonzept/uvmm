/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

/**
 * \file MSI-X structures and constants
 */

#include <l4/sys/icu>
#include <l4/cxx/static_vector>

namespace Vdev { namespace Msix {

enum Table_entry_const
{
  Vector_ctrl_mask_bit = 0x1,
  Data_vector_mask = 0xff,
  Entry_size = 16,      // entry size in bytes: 4 DWORDs.
};

enum
{
  Address_interrupt_prefix = 0xfee,
};

/// MSI-X address: Interrupt request compatibility format (Intel)
struct Interrupt_request_compat
{
  l4_uint64_t raw;
  CXX_BITFIELD_MEMBER_RO(32, 63, reserved0_2, raw);
  CXX_BITFIELD_MEMBER_RO(20, 31, fixed, raw);
  CXX_BITFIELD_MEMBER_RO(12, 19, dest_id, raw);
  CXX_BITFIELD_MEMBER_RO(4, 11, reserved0_1, raw);
  CXX_BITFIELD_MEMBER_RO(3, 3, redirect_hint, raw);
  CXX_BITFIELD_MEMBER_RO(2, 2, dest_mode, raw);
  CXX_BITFIELD_MEMBER_RO(0, 1, reserved_0, raw);

  explicit Interrupt_request_compat(l4_uint64_t addr) : raw(addr) {};
};

/// MSI-X data format (Intel)
struct Data_register_format
{
  // Intel SDM Vol. 3A 10-35, October 2017
  l4_uint32_t raw;
  CXX_BITFIELD_MEMBER_RO(15, 15, trigger_mode, raw);
  CXX_BITFIELD_MEMBER_RO(14, 14, trigger_level, raw);
  CXX_BITFIELD_MEMBER_RO(8, 10, delivery_mode, raw);
  CXX_BITFIELD_MEMBER_RO(0, 7, vector, raw);

  explicit Data_register_format(l4_uint32_t data) : raw(data) {};
};

struct Table_entry
{
  /* The structure defined in the PCI spec V.3.0 is as follows:
   * Each table entry consists of four DWORDs (32 bits), overall 128 bits.
   * [    127:96     |     95:64    |        63:32      |       31:0      ]
   * [Vector control | Message Data | Message Addr high | Message Addr low]
   */
  l4_uint64_t addr;
  l4_uint32_t data;
  l4_uint32_t vector_ctrl;

  Table_entry() : vector_ctrl(Vector_ctrl_mask_bit) {}

  /// True if the entry is masked.
  bool masked() const { return vector_ctrl & Vector_ctrl_mask_bit; }
  void mask() { vector_ctrl |= Vector_ctrl_mask_bit; }
  void unmask() { vector_ctrl &= ~Vector_ctrl_mask_bit; }

  /// Print entry
  void dump() const
  {
    Dbg().printf("Addr 0x%llx, Data 0x%x, ctrl 0x%x\n", addr, data, vector_ctrl);
  }
};

/**
 * Device local MSI-X table structure.
 */
class Table
{
public:
  /**
   * \param memory           Backing memory allocated by device.
   * \param max_num_entires  As encoded in MSI-X message control plus one.
   */
  explicit Table(l4_addr_t memory, unsigned const max_num_entries)
  : _table(reinterpret_cast<Table_entry *>(memory), max_num_entries)
  {}

  /**
   * \param first_entry      Backing memory allocated by device.
   * \param max_num_entires  As encoded in MSI-X message control plus one.
   */
  explicit Table(Table_entry *first_entry, unsigned max_num_entries)
  : _table(first_entry, max_num_entries)
  {}

  /// Read the table entry at `idx`
  Table_entry &entry(unsigned idx)
  {
    assert(idx < _table.size());
    return _table[idx];
  }

  /// Get the start address of the table.
  l4_addr_t start() const
  {
    return reinterpret_cast<l4_addr_t>(_table.begin());
  }

  /// Print all table entries.
  void dump() const
  {
    for (Table_entry const &e : _table)
      e.dump();
  }

private:
  cxx::static_vector<Table_entry> _table;
}; // class Table;

} } // namespace Vdev::Msix
