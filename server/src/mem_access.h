/*
 * Copyright (C) 2017, 2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/err.h>
#include <l4/sys/l4int.h>
#include <l4/sys/cache.h>

namespace Vmm {

/**
 * Describes a load/store instruction.
 */
struct Mem_access
{
  enum Kind
  {
    Load,  /// load from memory
    Store, /// store to memory
    Other  /// unknown instruction
  };

  enum Width
  {
    Wd8 = 0,  // Byte access
    Wd16 = 1, // Half-word access
    Wd32 = 2, // Word access
    Wd64 = 3, // Double word access
  };

  l4_uint64_t value;
  Kind access;
  char width;

  static l4_uint64_t read_width(l4_addr_t addr, char width)
  {
    // only naturally aligned accesses are allowed
    if (L4_UNLIKELY(addr & ((1UL << width) - 1)))
      return 0;

    switch (width) {
      case Wd8:  return *reinterpret_cast<l4_uint8_t volatile *>(addr);
      case Wd16: return *reinterpret_cast<l4_uint16_t volatile *>(addr);
      case Wd32: return *reinterpret_cast<l4_uint32_t volatile *>(addr);
      case Wd64: return *reinterpret_cast<l4_uint64_t volatile *>(addr);
      default: break;
    }

    // other widths are unsupported
    return 0;
  }

  static int write_width(l4_addr_t addr, l4_uint64_t value, char width)
  {
    // only naturally aligned accesses are allowed
    if (L4_UNLIKELY(addr & ((1UL << width) - 1)))
      return -L4_EINVAL;

    switch (width)
      {
      case Wd8:  *reinterpret_cast<l4_uint8_t volatile *>(addr) = value;  break;
      case Wd16: *reinterpret_cast<l4_uint16_t volatile *>(addr) = value; break;
      case Wd32: *reinterpret_cast<l4_uint32_t volatile *>(addr) = value; break;
      case Wd64: *reinterpret_cast<l4_uint64_t volatile *>(addr) = value; break;
      default: return -L4_EINVAL;
      }

    return L4_EOK;
  }

  static int cache_clean_data_width(l4_addr_t addr, char width)
  {
    switch (width)
      {
      case Wd8:  l4_cache_clean_data(addr, addr + 1); break;
      case Wd16: l4_cache_clean_data(addr, addr + 2); break;
      case Wd32: l4_cache_clean_data(addr, addr + 4); break;
      case Wd64: l4_cache_clean_data(addr, addr + 8); break;
      default: return -L4_EINVAL;
      }

    return L4_EOK;
  }

  template<typename STORAGE>
  static STORAGE read(STORAGE v, unsigned offs, char width)
  {
    if ((1u << width) >= sizeof(STORAGE))
      return v;

    unsigned const szm = sizeof(STORAGE) - 1;
    unsigned const sh = (offs & (szm << width) & szm) * 8;
    STORAGE const m = ~((~static_cast<STORAGE>(0)) << (8 << width));
    return (v >> sh) & m;
  }

  template<typename STORAGE, typename VAL>
  static void write(STORAGE *s, VAL v, unsigned offs, char width)
  {
    if ((1u << width) >= sizeof(STORAGE))
      {
        *s = v;
      }
    else
      {
        unsigned const szm = sizeof(STORAGE) - 1;
        unsigned const sh = (offs & (szm << width) & szm) * 8;
        STORAGE const m = ~((~static_cast<STORAGE>(0)) << (8 << width)) << sh;
        *s = (*s & ~m) | (static_cast<STORAGE>(v) & m);
      }
  }
};

}
