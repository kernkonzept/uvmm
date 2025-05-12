/*
 * Copyright (C) 2019-2021, 2023-2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

/**
 * \file MSI-X structures and constants
 */

namespace Vdev { namespace Msix {

enum Table_entry_const
{
  Vector_ctrl_mask_bit = 0x1,
  Entry_size = 16,      // entry size in bytes: 4 DWORDs.
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

inline size_t msix_table_mem_size(unsigned max_msix_entries)
{
  return l4_round_page(sizeof(Table_entry) * max_msix_entries);
};

inline size_t msix_table_pba_mem_size(unsigned max_msix_entries)
{
  return msix_table_mem_size(max_msix_entries) + L4_PAGESIZE;
};

} } // namespace Vdev::Msix
