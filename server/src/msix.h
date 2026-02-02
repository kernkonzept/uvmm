/*
 * Copyright (C) 2019-2021, 2023-2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/cxx/bitmap>

/**
 * \file MSI-X structures and constants
 */

namespace Vdev { namespace Msix {

enum Table_entry_const
{
  Vector_ctrl_mask_bit = 0x1,
  Entry_size = 16,      // entry size in bytes: 4 DWORDs.
  Offset_addr_low = 0,
  Offset_addr_high = 4,
  Offset_data = 8,
  Offset_ctrl = 12,
};

struct Table_entry
{
  /* The structure defined in the PCI spec V.3.0 is as follows:
   * Each table entry consists of four DWORDs (32 bits), overall 128 bits.
   * [    127:96     |     95:64    |        63:32      |       31:0      ]
   * [Vector control | Message Data | Message Addr high | Message Addr low]
   */
  l4_uint64_t addr = 0;
  l4_uint32_t data = 0;
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
static_assert(sizeof(Table_entry) == 16,
              "MSI-X table entry size conforms to specification.");


class Pending_bit_array
{
public:
  enum { Max_size = L4_PAGESIZE };

  // The memory for the pending-bit array is externally managed.
  Pending_bit_array(l4_addr_t addr, unsigned num_msix_entries)
  : _num_bits(num_msix_entries),
    _bm(reinterpret_cast<void *>(addr))
  {
    assert(Max_size >= _bm.bit_buffer_bytes(_num_bits));
    clear_all();
  }

  void clear_all()
  { memset(_bm.bit_buffer(), 0U, _bm.bit_buffer_bytes(_num_bits)); }

  void set(unsigned idx)
  { _bm.atomic_set_bit(idx); }

  void clear(unsigned idx)
  { _bm.atomic_clear_bit(idx); }

  bool is_set(unsigned idx)
  { return _bm.bit(idx); }

  void write(unsigned reg, char /*size*/, l4_umword_t /*value*/)
  {
    info().printf("Ignore write to read-only pending bit array at 0x%x.\n",
                  reg);
  }

private:
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "vMSI-X PBA"); }

  unsigned _num_bits;
  cxx::Bitmap_base _bm;
};

inline size_t msix_table_mem_size(unsigned max_msix_entries)
{
  return l4_round_page(sizeof(Table_entry) * max_msix_entries);
};

inline size_t msix_table_pba_mem_size(unsigned max_msix_entries)
{
  return msix_table_mem_size(max_msix_entries) + Pending_bit_array::Max_size;
};

} } // namespace Vdev::Msix
