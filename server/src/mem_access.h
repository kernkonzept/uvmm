/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/err.h>
#include <l4/sys/l4int.h>

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
      case Wd8:  return *reinterpret_cast<l4_uint8_t *>(addr);
      case Wd16: return *reinterpret_cast<l4_uint16_t *>(addr);
      case Wd32: return *reinterpret_cast<l4_uint32_t *>(addr);
      case Wd64: return *reinterpret_cast<l4_uint64_t *>(addr);
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
      case Wd8:  *reinterpret_cast<l4_uint8_t *>(addr) = value;  break;
      case Wd16: *reinterpret_cast<l4_uint16_t *>(addr) = value; break;
      case Wd32: *reinterpret_cast<l4_uint32_t *>(addr) = value; break;
      case Wd64: *reinterpret_cast<l4_uint64_t *>(addr) = value; break;
      default: return -L4_EINVAL;
      }

    return L4_EOK;
  }

};

}
