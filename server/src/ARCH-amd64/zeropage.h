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
#include "vm_ram.h"

namespace Vmm {

enum class Binary_type
{
  Elf,
  Linux
};

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

  void add_cmdline(char const *line)
  {
    info().printf("Cmd_line: %s\n", line);

    // strlen excludes the terminating '\0', strcpy copies it. The length check
    // must care for that additional byte.
    if (strlen(line) >= Max_cmdline_size - 1)
      L4Re::chksys(-L4_EINVAL, "Maximal command line size is 4095 characters.");

    strcpy(_cmdline, line);
  }

  void add_ramdisk(l4_uint64_t start, l4_uint64_t sz)
  {
    _ramdisk_start = start;
    _ramdisk_size = sz;
  }

  void cfg_e820(Vm_ram *ram)
  {
    l4_addr_t last_addr = 0;
    ram->foreach_region([this, &last_addr](Vmm::Ram_ds const &r)
      {
        if (_e820_idx < Max_e820_entries)
          add_e820_entry(r.vm_start().get(), r.size(), E820_ram);
        last_addr = r.vm_start().get() + r.size();
      });

    // e820 memory map: Linux expects at least two entries to be present to
    // qualify as a e820 map. From our side, the second entry is currently
    // unused and has no backing memory. see linux/boot/x86/kernel/e820.c
    if (last_addr && _e820_idx < 2)
      add_e820_entry(last_addr, L4_PAGESIZE , E820_reserved);
  }

  /**
   * Add a device tree.
   *
   * \param dt_addr  Address of the device tree in guest RAM.
   * \param size     Size of the device tree.
   */
  void add_dtb(l4_addr_t dt_addr, l4_size_t size)
  {
    _dtb_boot_addr = dt_addr;
    _dtb_size = size;
  }

  void write(Vm_ram *ram, Binary_type const gt)
  {
    memset(ram->guest2host<void *>(_gp_addr), 0, L4_PAGESIZE);

    // boot_params are setup according to v.2.07
    unsigned boot_protocol_version = 0x207;

    switch (gt)
      {
      case Binary_type::Elf:
        // Note: The _kbinary variable contains the ELF binary entry
        write_dtb(ram);
        set_header<l4_addr_t>(ram, Bp_code32_start, _kbinary.get());
        set_header<l4_uint32_t>(ram, Bp_signature, 0x53726448); // "HdrS"

        boot_protocol_version = 0x209; // DTS needs v.2.09

        info().printf("Elf guest zeropage: dtb 0x%llx, entry 0x%lx\n",
                      get_header<l4_uint64_t>(ram, Bp_setup_data),
                      get_header<l4_addr_t>(ram, Bp_code32_start));
        break;

      case Binary_type::Linux:
        {
          // Note: The _kbinary variable contains start of the kernel binary

          // constants taken from $lx_src/Documentation/x86/boot.txt
          l4_uint8_t hsz = *ram->guest2host<unsigned char *>(_kbinary + 0x0201);

          // calculate size of the setup_header in the zero page/boot params
          l4_size_t boot_hdr_size = (0x0202 + hsz) - Bp_boot_header;

          memcpy(ram->guest2host<void *>(_gp_addr + Bp_boot_header),
                 ram->guest2host<void *>(_kbinary + Bp_boot_header),
                 boot_hdr_size);
          break;
        }
      }

    write_cmdline(ram);

    // write e820
    assert(_e820_idx > 0);
    memcpy(ram->guest2host<void *>(_gp_addr + Bp_e820_map), _e820,
           sizeof(E820_entry) * _e820_idx);
    set_header<l4_uint8_t>(ram, Bp_e820_entries, _e820_idx);

    // write RAM disk
    set_header<l4_uint32_t>(ram, Bp_ramdisk_image, _ramdisk_start);
    set_header<l4_uint32_t>(ram, Bp_ramdisk_size, _ramdisk_size);
    if ((_ramdisk_start + _ramdisk_size) >> 32 > 0)
      {
        Xloadflags xlf;
        xlf.can_be_loaded_above_4g() = 1;
        set_header<l4_uint16_t>(ram, Bp_xloadflags, xlf.raw);
        set_header<l4_uint32_t>(ram, Bp_ext_ramdisk_image, _ramdisk_start >> 32);
        set_header<l4_uint32_t>(ram, Bp_ext_ramdisk_size, _ramdisk_size >> 32);

        boot_protocol_version = 0x212; // xloadflags needs v.2.12
      }

    // misc stuff in the boot header
    set_header<l4_uint8_t>(ram, Bp_type_of_loader, 0xff);
    set_header<l4_uint16_t>(ram, Bp_version, boot_protocol_version);

    set_header<l4_uint8_t>(ram, Bp_loadflags,
                           get_header<l4_uint8_t>(ram, Bp_loadflags)
                             | Bp_loadflags_keep_segments_bit);
  }

  Vmm::Guest_addr addr() const { return _gp_addr; }

  l4_uint32_t entry(Vm_ram *ram)
  { return get_header<l4_uint32_t>(ram, Bp_code32_start); }

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

  // add an entry to the single-linked list of Setup_data
  void add_setup_data(Vm_ram *ram, Setup_data *sd, l4_addr_t guest_addr)
  {
    sd->next = get_header<l4_uint64_t>(ram, Bp_setup_data);
    set_header<l4_uint64_t>(ram, Bp_setup_data, guest_addr);
  }

  void write_cmdline(Vm_ram *ram)
  {
    if (*_cmdline == 0)
      return;

    // place the command line behind the boot parameters
    auto cmdline_addr = (_gp_addr + Bp_end).round_page();

    strcpy(ram->guest2host<char *>(cmdline_addr), _cmdline);
    set_header<l4_uint32_t>(ram, Bp_cmdline_ptr, cmdline_addr.get());
    set_header<l4_uint32_t>(ram, Bp_cmdline_size, strlen(_cmdline));

    info().printf("cmdline check: %s\n", ram->guest2host<char *>(cmdline_addr));
  }

  void write_dtb(Vm_ram *ram)
  {
    if (_dtb_boot_addr == 0 || _dtb_size == 0)
      return;

    // dt_boot_addr is the guest address of the DT memory; Setup_data.data
    // must be the first byte of the DT. The rest of the Setup_data struct
    // must go right before it. Hopefully, there is space.
    unsigned sd_hdr_size = sizeof(Setup_data) + sizeof(Setup_data::data);
    auto dtb = ram->boot2guest_phys(_dtb_boot_addr);
    auto *sd = ram->guest2host<Setup_data *>(dtb - sd_hdr_size);

    for (unsigned i = sd_hdr_size; i > 0; i -= sizeof(char))
      {
        auto *sd_ptr = reinterpret_cast<char *>(sd);
        if (*sd_ptr)
          L4Re::chksys(-L4_EEXIST, "DTB Setup_data header memory in use.");
        sd_ptr++;
      }

    sd->type = Setup_dtb;
    sd->len = _dtb_size;
    // sd->data is the first DT byte.
    add_setup_data(ram, sd, _dtb_boot_addr - sd_hdr_size);
  }

  template <typename T>
  void set_header(Vm_ram *ram, unsigned field, T value)
  { *ram->guest2host<T *>(_gp_addr + field) = value; }

  template <typename T>
  T get_header(Vm_ram *ram, unsigned field)
  { return *ram->guest2host<T *>(_gp_addr + field); }
};

} // namespace Vmm
