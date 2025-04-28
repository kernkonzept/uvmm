/*
 * Copyright (C) 2016-2017, 2021, 2024 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/sys/l4int.h>
#include <l4/sys/consts.h>

namespace Vmm {

enum Handler_return_codes
{
  Retry = 0,
  Jump_instr = 1,
  Invalid_opcode = 2,     // Handled on amd64 only.
  Stack_fault = 3,        // Handled on amd64 only.
  General_protection = 4, // Handled on amd64 only.
};

enum
{
  Ram_hugepageshift  = 24,
  Ram_hugepagesize   = 1UL << Ram_hugepageshift,
};

/**
 * Check whether a log2-sized page containing address is inside a region
 *
 * \param align    log2 of the page alignment.
 * \param addr     Address to check.
 * \param start    Start of region.
 * \param end      Last byte of region; do not check end of region if zero.
 * \return true if there is a log2-aligned page containing the address
 *                 inside the region
 */
inline bool log2_page_in_range(unsigned char align, l4_addr_t addr,
                               l4_addr_t start, l4_addr_t end)
{
  auto log2page = l4_trunc_size(addr, align);
  return    start <= log2page
         && (!end || (log2page + (1UL << align) - 1) <= end);
}

inline bool log2_alignment_compatible(unsigned char align, l4_addr_t addr1,
                                      l4_addr_t addr2)
{ return (addr1 & ((1UL << align) - 1)) == (addr2 & ((1UL << align) - 1)); }

/**
 * Calculate log_2(pagesize) for a location in a region
 *
 * \param addr     Guest-physical address where the access occurred.
 * \param start    Guest-physical address of start of memory region.
 * \param end      Guest-physical address of last byte of memory region.
 * \param offset   Accessed address relative to the beginning of the region.
 * \param l_start  Local address of start of memory region, default 0.
 * \param l_end    Local address of end of memory region, default 0.
 *
 * \return largest possible pageshift.
 */
inline char get_page_shift(l4_addr_t addr, l4_addr_t start, l4_addr_t end,
                           l4_addr_t offset, l4_addr_t l_start = 0,
                           l4_addr_t l_end = 0)
{
  if (end <= start)
    return L4_PAGESHIFT;

  // Start with a reasonable maximum value: log2 of the memory region size
  l4_addr_t const size = end - start + 1;
  unsigned char align = sizeof(l4_addr_t) * 8 - (__builtin_clzl(size) + 1);
  for (; align > L4_PAGESHIFT; --align)
    {
      // Check whether a log2-sized page is inside the regions
      if (   !log2_page_in_range(align, addr, start, end)
          || !log2_page_in_range(align, l_start + offset, l_start, l_end))
        continue;

      if (!log2_alignment_compatible(align, start, l_start))
        continue;

      return align;
    }

  return L4_PAGESHIFT;
}

} // namespace Vmm
