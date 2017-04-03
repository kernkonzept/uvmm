/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>

#include "debug.h"
#include "ram_ds.h"

namespace Vmm {

enum Boot_param
{
  Bp_ext_ramdisk_image = 0x0c0,
  Bp_ext_ramdisk_size = 0x0c4,
  Bp_ext_cmd_line_ptr = 0x0c8,
  Bp_e820_entries = 0x1e8,
  Bp_boot_header = 0x1f1,
  Bp_setup_sects = 0x1f1,
  Bp_signature = 0x202,
  Bp_version = 0x206,
  Bp_type_of_loader = 0x210,
  Bp_loadflags = 0x211,
  Bp_code32_start = 0x214,
  Bp_ramdisk_image = 0x218,
  Bp_ramdisk_size = 0x21c,
  Bp_cmdline_ptr = 0x228,
  Bp_ext_loader_ver = 0x226,
  Bp_ext_loader_type = 0x227,
  Bp_init_size = 0x260,
  Bp_e820_map = 0x2d0,
  Bp_end = 0xeed, // after EDD data array
};

class Zeropage
{
  enum E820_types
  {
    E820_ram = 1,
    E820_reserved = 2
  };

  struct E820_entry
  {
    l4_uint64_t addr; // start of segment
    l4_uint64_t size;
    l4_uint32_t type;
  } __attribute__((packed));

  enum
  {
    Max_cmdline_size = 200,
    Max_e820_entries = 5,

    Bp_loadflags_keep_segments_bit = 0x40
  };

  l4_addr_t _gp_addr; /// VM physical address
  l4_addr_t const _kbinary; // VM physical address

  char _cmdline[Max_cmdline_size];
  E820_entry _e820[Max_e820_entries];
  unsigned _e820_idx = 0;
  l4_uint32_t _ramdisk_start = 0;
  l4_uint32_t _ramdisk_size = 0;

public:
  Zeropage(l4_addr_t addr, l4_addr_t kernel)
  : _gp_addr(addr), _kbinary(kernel)
  {
    info().printf("Zeropage @ 0x%lx, Kernel @ 0x%lx\n", addr, kernel);
  }

  void add_cmdline(char const *line)
  {
    info().printf("Cmd_line: %s\n", line);
    assert(strlen(line) < Max_cmdline_size);
    strcpy(_cmdline, line);
  }

  void add_ramdisk(l4_uint32_t start, l4_uint32_t sz)
  {
    _ramdisk_start = start;
    _ramdisk_size = sz;
  }

  void cfg_e820(l4_size_t ram_sz)
  {
    // e820 memory map: Linux expects at least two entries to be present to
    // qualify as a e820 map. From our side, the second entry is currently
    // unused and has no backing memory. see linux/boot/x86/kernel/e820.c
    add_e820_entry(0, ram_sz, E820_ram);
    add_e820_entry(ram_sz, L4_PAGESIZE , E820_reserved);
  }

  void write(Ram_ds *ram)
  {
    // constants taken from $lx_src/Documentation/x86/boot.txt
    l4_uint8_t hsz = *(reinterpret_cast<unsigned char *>(
      ram->access(L4virtio::Ptr<char>(_kbinary + 0x0201))));

    // calculate size of the setup_header in the zero page/boot params
    l4_size_t boot_hdr_size = (0x0202 + hsz) - Bp_boot_header;

    memcpy(ram->access(L4virtio::Ptr<char>(_gp_addr + Bp_boot_header)),
           ram->access(L4virtio::Ptr<char>(_kbinary + Bp_boot_header)),
           boot_hdr_size);

    assert(strlen(_cmdline) > 0);
    strcpy(ram->access(L4virtio::Ptr<char>(_gp_addr + Bp_end)),
           _cmdline);

    set_header<l4_uint32_t>(ram, Bp_cmdline_ptr, _gp_addr + Bp_end);

    info().printf("cmdline check: %s\n",
                  ram->access(L4virtio::Ptr<char>(_gp_addr + Bp_end)));

    assert(_e820_idx > 0);
    memcpy(ram->access(L4virtio::Ptr<char>(_gp_addr + Bp_e820_map)),
           _e820,
           sizeof(E820_entry) * _e820_idx);
    set_header<l4_uint8_t>(ram, Bp_e820_entries, _e820_idx);

    set_header<l4_uint32_t>(ram, Bp_ramdisk_image, _ramdisk_start);
    set_header<l4_uint32_t>(ram, Bp_ramdisk_size, _ramdisk_size);

    // misc stuff in the boot header
    set_header<l4_uint8_t>(ram, Bp_type_of_loader, 0xff);
    set_header<l4_uint16_t>(ram, Bp_version, 0x207);

    set_header<l4_uint8_t>(ram, Bp_loadflags,
                           get_header<l4_uint8_t>(ram, Bp_loadflags)
                             | Bp_loadflags_keep_segments_bit);
  }

  l4_addr_t addr() const { return _gp_addr; }

  char *entry(Ram_ds *ram)
  { return ram->access(L4virtio::Ptr<char>(_kbinary + Bp_code32_start)); }

private:
  static Dbg trace() { return Dbg(Dbg::Core, Dbg::Trace); }
  static Dbg info() { return Dbg(Dbg::Core, Dbg::Info); }

  void add_e820_entry(l4_uint64_t addr, l4_uint64_t size, l4_uint32_t type)
  {
    assert(_e820_idx < Max_e820_entries);
    _e820[_e820_idx].addr = addr;
    _e820[_e820_idx].size = size;
    _e820[_e820_idx].type = type;

    _e820_idx++;
  }

  template <typename T>
  void set_header(Ram_ds *ram, unsigned field, T value)
  {
    *(reinterpret_cast<T *>(
      ram->access(L4virtio::Ptr<char>(_gp_addr + field)))) = value;
  }

  template <typename T>
  T get_header(Ram_ds *ram, unsigned field)
  {
    return *(reinterpret_cast<T *>(
      ram->access(L4virtio::Ptr<char>(_gp_addr + field))));
  }
};

} // namespace Vmm
