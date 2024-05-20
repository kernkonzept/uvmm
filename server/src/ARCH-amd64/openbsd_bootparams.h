/*
 * Copyright (C) 2023-2024 genua GmbH, 85551 Kirchheim, Germany
 * All rights reserved. Alle Rechte vorbehalten.
 */
/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/sys/types.h>

#include "debug.h"
#include "vm_ram.h"

namespace Vmm::Openbsd {

// See OpenBSD: sys/stand/boot/bootarg.h
enum
{
  Bapiv_ancient  = 0x00000000,      /* MD old i386 bootblocks */
  Bapiv_vars     = 0x00000001,      /* MD structure w/ add info passed */
  Bapiv_vector   = 0x00000002,      /* MI vector of MD structures passed */
  Bapiv_env      = 0x00000004,      /* MI environment vars vector */
  Bapiv_bmemmap  = 0x00000008,      /* MI memory map passed is in bytes */
  Bootarg_apiver = (Bapiv_vector|Bapiv_env|Bapiv_bmemmap),
  Bootarg_end    = -1,
  Bootarg_memmap = 0,
};

struct Boot_args
{
  l4_int32_t ba_type;
  l4_int32_t ba_size;
  l4_int32_t ba_next;
   //struct _boot_args *ba_next;
  char ba_arg[1];
} __attribute__((packed));
static_assert(sizeof(Boot_args) == 13,
              "Size of packed Boot_args struct is as expected.");

// See OpenBSD: sys/arch/amd64/include/biosvar.h
enum
{
  Bios_map_end  = 0x00,   /* End of array XXX - special */
  Bios_map_free = 0x01,   /* Usable memory */
  Bios_map_res  = 0x02,   /* Reserved memory */
  Bios_map_acpi = 0x03,   /* ACPI Reclaim memory */
  Bios_map_nvs  = 0x04,   /* ACPI NVS memory */
};

struct Bios_memmap
{
  l4_uint64_t addr;          /* Beginning of block */
  l4_uint64_t size;          /* Size of block */
  l4_uint32_t type;          /* Type of block */
} __attribute__((packed));
static_assert(sizeof(Bios_memmap) == 20,
              "Size of packed Bios_memmap struct is as expected.");

enum
{
  Bootarg_consdev = 5,
};

struct Bios_consdev
{
  l4_int32_t  consdev;
  l4_int32_t  conspeed;
  l4_uint64_t consaddr;
  l4_int32_t  consfreq;
  l4_uint32_t flags;
  l4_int32_t  reg_width;
  l4_int32_t  reg_shift;
} __attribute__((packed));
static_assert(sizeof(Bios_consdev) == 32,
              "Size of packed Bios_consdev struct is as expected.");

// See OpenBSD: sys/dev/isa/isareg.h
enum
{
  Iom_end = 0x100000 /* End of I/O Memory "hole" */
};

// See OpenBSD: sys/sys/types.h
static constexpr unsigned makedev_obsd(unsigned x, unsigned y)
{
  return ((((x) & 0xff) << 8) | ((y) & 0xff) | (((y) & 0xffff00) << 8));
}

// Memory layout for kernel entry function stack with parameters
// This assembles the memory stack for the legacy exec call in OpenBSD
// file sys/arch/amd64/stand/libsa/exec_i386.c
struct Openbsd_entry_stack
{
  l4_uint32_t returnaddr; // unused
  l4_uint32_t howto; // int
  l4_uint32_t bootdev; // dev_t
  l4_uint32_t apiversion; // api version of /boot
  l4_uint32_t end; // End address of loaded kernel binary
  l4_uint32_t extmem; // extended memory, unused
  l4_uint32_t cnvmem; // base memory reported by bios
  l4_uint32_t ac; // Length of bootargs
  l4_uint32_t av; // Offset of bootargs
} __attribute__((packed));
static_assert(sizeof(Openbsd_entry_stack) == 36,
              "Size of packed Openbsd_entry_stack struct is as expected.");

class Boot_params
{
public:
  enum
  {
    Phys_mem_addr = L4_PAGESIZE, ///< Location of the OpenBSD boot parameters
  };

  Boot_params(Vmm::Guest_addr addr, l4_addr_t kernel,
                     l4_addr_t kernel_size)
  : _gp_addr(addr), _bootargs(nullptr), _bootargs_size(0)
  {
    info().printf("Boot_params @ 0x%lx, Kernel @ 0x%lx (size=%ld)\n",
                  addr.get(), kernel, kernel_size);
    memset(static_cast<void *>(&_params), 0, sizeof(Openbsd_entry_stack));
    _params.apiversion = Bootarg_apiver;

    _params.cnvmem = Iom_end;
    _params.ac = 0;
    _params.av = 0;

    _params.end = kernel + kernel_size;
  }

  /**
   * Print OpenBSD Boot Parameters on console
   */
  void dump();

  /**
   * Write boot parameters into guest memory
   */
  void write(Vm_ram *ram);

private:
  /**
   * Add memory to memory map
   */
  void add_to_memmap(Bios_memmap **map, size_t const num, l4_uint32_t type,
                     l4_uint64_t addr, l4_uint64_t size);

  /**
   * Prepare memory map for OpenBSD guest
   */
  void setup_memmap(Vm_ram *ram);

  /**
   * Get guest physical address
   */
  Vmm::Guest_addr addr() const { return _gp_addr; }

  /**
   * Add boot argument to linked list.
   *
   * \note The data is copied into an internal buffer.
   *       The caller retains ownership of p.
   */
  void add_bootarg(int t, size_t l, void const *p);

private:
  static Dbg trace() { return Dbg(Dbg::Core, Dbg::Trace, "OpenBSDBoot"); }
  static Dbg info() { return Dbg(Dbg::Core, Dbg::Info, "OpenBSDBoot"); }

  /**
   * Guest physical address of first page
   */
  Vmm::Guest_addr _gp_addr;

  /**
   * Entry stack
   */
  Openbsd_entry_stack _params;

  /**
   * Blob containing chained boot argument structs of varying sizes
   */
  void *_bootargs;

  /**
   * Size of `_bootargs` in bytes
   */
  size_t _bootargs_size;
};

} // namespace Vmm::Openbsd
