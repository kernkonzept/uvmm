/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <limits>

#include <l4/cxx/minmax>
#include <l4/sys/l4int.h>

#include "monitor_args.h"

namespace Monitor {

/**
 * Memory dumping helper class.
 */
class Mem_dumper
{
  // dumping blocks larger than this constant will result in an error
  enum : l4_size_t { Max_displayable_entries = 1024 };

public:
  /**
   * Initialize memory dumper from parameter string.
   *
   * \param args  Must be of the form `<addr> [<n> [<w>]]`
   *              where: * `<addr>` is the starting address of the memory block.
   *                     * `<n>` is the number of entries to be dumped.
   *                     * `<w>` is either of b (byte), w (word, 16 bits),
   *                       d (double word) or q (quad word).
   *              and `<n>` and `<w>` default to 1 and d respectively.
   *
   * \throws L4::Runtime_error  On malformed parameter string.
   */
  Mem_dumper(Arglist *args)
  {
    _addr = args->pop<l4_addr_t>("Failed to parse address");

    _num_entries = args->pop<l4_size_t>(1, "Failed to parse number of entries");

    if (!args->empty())
      {
        auto byte_width = args->pop<std::string>("Missing byte width specifier");

        if (byte_width == "b")
          _bytes_per_entry = 1;
        else if (byte_width == "w")
          _bytes_per_entry = 2;
        else if (byte_width == "d")
          _bytes_per_entry = 4;
        else if (byte_width == "q")
          _bytes_per_entry = 8;
        else
          argument_error("Invalid byte width specifier");
      }
    else
      // note that we default to the host word size here and not that of the
      // guest (which may be different, e.g. on ARM, but determining it is
      // not trivial)
      _bytes_per_entry = sizeof(l4_addr_t);

    _addr = align_addr(_addr, _bytes_per_entry);

    // ensure that addr + _num_entries * _bytes_per_entry is not larger than the
    // largest representable address (by decreasing _num_entries if necessary).
    l4_size_t max_entries =
      (std::numeric_limits<l4_addr_t>::max() - _addr) / _bytes_per_entry;

    _num_entries = cxx::min(_num_entries, max_entries);

    // limit the number of displayed entries to a fixed maximum
    _num_entries = cxx::min(_num_entries,
                            static_cast<l4_size_t>(Max_displayable_entries));

    if (_num_entries == 0)
      argument_error("Nothing to dump");
  }

  /**
   * Memory block address specified in parameter string.
   *
   * \return  Starting address of memory block to be dumped.
   */
  l4_addr_t addr_start() const
  { return _addr; }

  /**
   * End of memory block to be dumped.
   *
   * \return  Address of first byte after memory block to be dumped.
   */
  l4_addr_t addr_end() const
  { return _addr + _num_entries * _bytes_per_entry; }

  /**
   * Size of memory block to be dumped.
   *
   * \return  Size (in bytes) of memory block to be dumped.
   */
  l4_addr_t block_size() const
  { return _num_entries * _bytes_per_entry; }

  /**
   * Dump memory block.
   *
   * \param f           Stream to which to write output.
   * \param addr_hvirt  Value return by `addr_start()` converted to a host
   *                    virtual address (conversion is left to the caller).
   * \param max_size    Upper limit on the size of the memory block to be
   *                    dumped (if this is not `0`, the actual size is
   *                    `max(max_size, <n> * |<w>|)`).
   *
   */
  void dump(FILE *f, l4_addr_t addr_hvirt, l4_size_t max_size = 0) const
  {
    l4_addr_t num_entries;
    if (max_size == 0 || max_size >= _num_entries * _bytes_per_entry)
      num_entries = _num_entries;
    else
      num_entries = max_size / _bytes_per_entry;

    for (l4_addr_t offs = 0; offs < num_entries; ++offs)
      {
        fprintf(f, "0x%016lx: ", _addr + offs * _bytes_per_entry);

        switch (_bytes_per_entry)
          {
          case 1:
            fprintf(f, "0x%02x", get_entry<l4_uint8_t>(addr_hvirt, offs));
            break;
          case 2:
            fprintf(f, "0x%04x", get_entry<l4_uint16_t>(addr_hvirt, offs));
            break;
          case 4:
            fprintf(f, "0x%08x", get_entry<l4_uint32_t>(addr_hvirt, offs));
            break;
          case 8:
            fprintf(f, "0x%016llx", get_entry<l4_uint64_t>(addr_hvirt, offs));
            break;
          }

        fputc('\n', f);
      }
  }

private:
  static l4_addr_t align_addr(l4_addr_t addr, unsigned bytes_per_entry)
  { return addr & ~(static_cast<l4_addr_t>(bytes_per_entry) - 1); }

  template<typename T>
  static T get_entry(l4_addr_t hvirt, l4_addr_t offs)
  { return *reinterpret_cast<T *>(hvirt + offs * sizeof(T)); }

  l4_addr_t _addr;
  l4_size_t _num_entries;
  unsigned _bytes_per_entry;
};

}
