/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017, 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include "zeropage.h"
#include "acpi.h"

namespace Vmm {

void Zeropage::add_cmdline(char const *line)
{
  info().printf("Cmd_line: %s\n", line);

  // strlen excludes the terminating '\0', strcpy copies it. The length check
  // must care for that additional byte.
  if (strlen(line) >= Max_cmdline_size - 1)
    L4Re::chksys(-L4_EINVAL, "Maximal command line size is 4095 characters.");

  strcpy(_cmdline, line);
}

void Zeropage::add_ramdisk(l4_uint64_t start, l4_uint64_t sz)
{
  _ramdisk_start = start;
  _ramdisk_size = sz;
}

void Zeropage::cfg_e820(Vm_ram *ram)
{
  l4_addr_t last_addr = 0;
  ram->foreach_region([this, &last_addr](Vmm::Ram_ds const &r)
  {
    if (_e820_idx < Max_e820_entries)
      add_e820_entry(r.vm_start().get(), r.size(),
                     r.writable() ? E820_ram : E820_reserved);
    last_addr = r.vm_start().get() + r.size();
  });

  auto facs = Acpi::Facs_storage::get()->mem_region();
  add_e820_entry(facs.start.get(), facs.end - facs.start + 1,
                 E820_reserved);

  // e820 memory map: Linux expects at least two entries to be present to
  // qualify as a e820 map. From our side, the second entry is currently
  // unused and has no backing memory. see linux/boot/x86/kernel/e820.c
  if (last_addr && _e820_idx < 2)
    add_e820_entry(last_addr, L4_PAGESIZE , E820_reserved);
}

void Zeropage::add_dtb(l4_addr_t dt_addr, l4_size_t size)
{
  _dtb_boot_addr = dt_addr;
  _dtb_size = size;
}

void Zeropage::set_screen_callback(std::function<void (void *)> cb)
{
  assert(!_screen_cb);
  _screen_cb = cb;
}

void Zeropage::write(Vm_ram *ram, Boot::Binary_type const gt)
{
  memset(ram->guest2host<void *>(_gp_addr), 0, L4_PAGESIZE);

  // boot_params are setup according to v.2.07
  unsigned boot_protocol_version = 0x207;

  switch (gt)
    {
    case Boot::Binary_type::Elf:
      // Note: The _kbinary variable contains the ELF binary entry
      write_dtb(ram);
      set_header<l4_addr_t>(ram, Bp_code32_start, _kbinary.get());
      set_header<l4_uint32_t>(ram, Bp_signature, 0x53726448); // "HdrS"

      boot_protocol_version = 0x209; // DTS needs v.2.09

      info().printf("Elf guest zeropage: dtb 0x%llx, entry 0x%lx\n",
                    get_header<l4_uint64_t>(ram, Bp_setup_data),
                    get_header<l4_addr_t>(ram, Bp_code32_start));
      break;

    case Boot::Binary_type::Linux:
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
    default:
      L4Re::throw_error(-L4_EINVAL, "Unsupported binary type.");
      break;
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

  // add screen info if necessary
  if (_screen_cb)
    _screen_cb(ram->guest2host<void *>(addr()));
}

void Zeropage::add_e820_entry(l4_uint64_t addr, l4_uint64_t size, l4_uint32_t type)
{
  assert(_e820_idx < Max_e820_entries);
  _e820[_e820_idx].addr = addr;
  _e820[_e820_idx].size = size;
  _e820[_e820_idx].type = type;

  _e820_idx++;
}

// add an entry to the single-linked list of Setup_data
void Zeropage::add_setup_data(Vm_ram *ram, Setup_data *sd, l4_addr_t guest_addr)
{
  sd->next = get_header<l4_uint64_t>(ram, Bp_setup_data);
  set_header<l4_uint64_t>(ram, Bp_setup_data, guest_addr);
}

void Zeropage::write_cmdline(Vm_ram *ram)
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

void Zeropage::write_dtb(Vm_ram *ram)
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

std::function<void (void *)> Zeropage::_screen_cb;
}
