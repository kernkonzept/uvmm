/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2018, 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <functional>

#include "debug.h"
#include "vm_ram.h"
#include "binary_loader.h"

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
  Bp_ext_loader_ver = 0x226,
  Bp_ext_loader_type = 0x227,
  Bp_cmdline_ptr = 0x228,
  Bp_xloadflags = 0x236,
  Bp_cmdline_size = 0x238,
  Bp_setup_data = 0x250,
  Bp_init_size = 0x260,
  Bp_e820_map = 0x2d0,
  Bp_end = 0xeed, // after EDD data array
};

class Zeropage
{
  struct Setup_data
  {
    l4_uint64_t next;
    l4_uint32_t type;
    l4_uint32_t len;
    l4_uint8_t data[0];
  };

  enum Setup_data_types
  {
    Setup_none = 0,
    Setup_e820_ext,
    Setup_dtb,
    Setup_pci,
    Setup_efi,
  };

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

  struct Xloadflags
  {
    l4_uint16_t raw = 0;
    /// Kernel has the legacy 64-bit entry point at 0x200.
    CXX_BITFIELD_MEMBER(0, 0, kernel_64, raw);
    /// Kernel/Boot_params/cmdline/ramdisk can be above 4G
    CXX_BITFIELD_MEMBER(1, 1, can_be_loaded_above_4g, raw);
    // bits 4:2 are EFI related; the remaining bits are unused;
  };

  enum
  {
    Max_cmdline_size = 4096,
    Max_e820_entries = 5,

    Bp_loadflags_keep_segments_bit = 0x40
  };

  Vmm::Guest_addr _gp_addr; ///< VM physical address of the zero page
  Vmm::Guest_addr const _kbinary; // VM physical address of the kernel binary

  char _cmdline[Max_cmdline_size];
  E820_entry _e820[Max_e820_entries];
  unsigned _e820_idx = 0;
  l4_uint64_t _ramdisk_start = 0;
  l4_uint64_t _ramdisk_size = 0;
  l4_addr_t _dtb_boot_addr = 0;
  l4_size_t _dtb_size = 0;

public:
  Zeropage(Vmm::Guest_addr addr, l4_addr_t kernel)
  : _gp_addr(addr), _kbinary(kernel)
  {
    info().printf("Zeropage @ 0x%lx, Kernel @ 0x%lx\n", addr.get(), kernel);
    memset(_cmdline, 0, Max_cmdline_size);
    memset(_e820, 0, Max_e820_entries * sizeof(E820_entry));
  }

  void add_cmdline(char const *line);
  void add_ramdisk(l4_uint64_t start, l4_uint64_t sz);

  void cfg_e820(Vm_ram *ram);

  /**
   * Add a device tree.
   *
   * \param dt_addr  Address of the device tree in guest RAM.
   * \param size     Size of the device tree.
   */
  void add_dtb(l4_addr_t dt_addr, l4_size_t size);

  static void set_screen_callback(std::function<void (void *)> cb);
  void write(Vm_ram *ram, Boot::Binary_type const gt);

  Vmm::Guest_addr addr() const { return _gp_addr; }

  l4_uint32_t entry(Vm_ram *ram)
  { return get_header<l4_uint32_t>(ram, Bp_code32_start); }

private:
  static std::function<void (void *)> _screen_cb;

  static Dbg trace() { return Dbg(Dbg::Core, Dbg::Trace); }
  static Dbg info() { return Dbg(Dbg::Core, Dbg::Info); }

  void add_e820_entry(l4_uint64_t addr, l4_uint64_t size, l4_uint32_t type);

  // add an entry to the single-linked list of Setup_data
  void add_setup_data(Vm_ram *ram, Setup_data *sd, l4_addr_t guest_addr);

  void write_cmdline(Vm_ram *ram);

  void write_dtb(Vm_ram *ram);

  template <typename T>
  void set_header(Vm_ram *ram, unsigned field, T value)
  { *ram->guest2host<T *>(_gp_addr + field) = value; }

  template <typename T>
  T get_header(Vm_ram *ram, unsigned field)
  { return *ram->guest2host<T *>(_gp_addr + field); }
};

} // namespace Vmm
