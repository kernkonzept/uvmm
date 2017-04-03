/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/util/cpu.h>
#include <l4/l4virtio/virtqueue>

#include "debug.h"
#include "ds_mmio_mapper.h"
#include "vm_memmap.h"

namespace Vmm {

class Pt_walker
{
public:
  Pt_walker(Vm_mem const *mmap)
  : _mmap(mmap),
    _levels {{Pml4_shift, Pml4_mask},
             {Pdpt_shift, Pdpt_mask},
             {Pd_shift, Pd_mask},
             {Pt_shift, Pt_mask}
            },
    cached_start(-1), cached_end(0), cached_ds_local_start(0)
  {
    int const max_phys_addr_bit = max_physical_address_bit();

    trace().printf("PT_walker: MAXPHYSADDR bits %i\n", max_phys_addr_bit);
    _phys_addr_mask_4k =
      ((1UL << max_phys_addr_bit) - 1) & ~((1UL << Phys_addr_4k) - 1);
    _phys_addr_mask_2m =
      ((1UL << max_phys_addr_bit) - 1) & ~((1UL << Phys_addr_2m) - 1);
    _phys_addr_mask_1g =
      ((1UL << max_phys_addr_bit) - 1) & ~((1UL << Phys_addr_1g) - 1);
  }

  l4_uint64_t walk(l4_uint64_t cr3, l4_uint64_t virt_addr)
  {
    trace().printf("cr3 0x%llx\n", cr3);
    l4_uint64_t *tbl = guest_phys(cr3);
    l4_uint64_t entry = _levels[0].get_entry(tbl, virt_addr);

    trace().printf("cr3 0x%llx, entry 0x%llx, vaddr 0x%llx\n", cr3, entry,
                   virt_addr);

    if (!(entry & Present_bit))
      throw L4::Runtime_error(-L4_EINVAL, "PML4 table not present\n");

    for (unsigned i = 1; i < Pt_levels; ++i)
      {
        // PML4Entry: no PAT bit (12) --> mask everything except [M-1:12]
        tbl = guest_phys(entry & _phys_addr_mask_4k);

        if (tbl == nullptr)
          {
            trace().printf("Level table ptr null for level %i\n", i);
            throw L4::Runtime_error(-L4_EINVAL, "No next level table found.\n");
          }

        entry = _levels[i].get_entry(tbl, virt_addr);

        if (!(entry & Present_bit))
          {
            trace().printf("entry not present 0x%llx\n", entry);
            throw L4::Runtime_error(-L4_EINVAL,
                                    "Found entry is not present.\n");
          }

        // check for PS = 0 in PDPT & PD entries
        if (entry & Pagesize_bit)
          {
            if (i == 1)
              return add_voffset(guest_phys(entry & _phys_addr_mask_1g),
                                 virt_addr & G1_offset_mask);
            else if (i == 2)
              return add_voffset(guest_phys(entry & _phys_addr_mask_2m),
                                 virt_addr & M2_offset_mask);
          }
      }

    return add_voffset(guest_phys(entry & _phys_addr_mask_4k),
                       virt_addr & K4_offset_mask);
  }

private:
  Vm_mem::value_type const *addr_to_mem(l4_uint64_t addr) const
  {
    Vm_mem::const_iterator f = _mmap->find(addr);
    if (f == _mmap->end())
      {
        Dbg().printf("Fail: 0x%llx memory not found.\n", addr);
        throw L4::Runtime_error(-L4_EINVAL, "No memory registered.");
      }

    return &*f;
  }

  Ds_handler const *mem_to_ds(Vm_mem::value_type const *mem) const
  {
    Ds_handler const *ds = dynamic_cast<Ds_handler *>(mem->second.get());
    if (!ds)
      throw L4::Runtime_error(-L4_EINVAL, "No Ds_handler registered\n");

    return ds;
  }

  l4_uint64_t *guest_phys(l4_uint64_t addr)
  {
    if (cached_start == -1U || cached_start > addr || cached_end < addr)
      {
        auto const *cached_mem = addr_to_mem(addr);
        cached_start = cached_mem->first.start;
        cached_end = cached_mem->first.end;
        cached_ds_local_start = mem_to_ds(cached_mem)->local_start();
      }

    auto *ret = reinterpret_cast<l4_uint64_t *>(
                  cached_ds_local_start + (addr & _phys_addr_mask_4k));
    trace().printf("Ram_addr: addr 0x%llx --> %p\n", addr, ret);
    return ret;
  }

  l4_uint64_t add_voffset(l4_uint64_t *addr, l4_uint64_t offset)
  {
    return reinterpret_cast<l4_uint64_t>(addr) + offset;
  }

  void dump_level(l4_uint64_t *tbl)
  {
    trace().printf("Dumping page table %p\n", tbl);
    for (int i = 0; i < 512; ++i)
      if (tbl[i] != 0 && tbl[i] & Present_bit)
        trace().printf("%i :: 0x%16llx\n", i, tbl[i]);
  }

  void dump_all_valid_entries(l4_uint64_t base_ptr)
  {
    trace().printf(" +++++ Dumping all entries ++++ \n");
    l4_uint64_t *tbl = reinterpret_cast<l4_uint64_t *>(base_ptr);
    for (int i = 0; i < 512; ++i)
      {
        if (tbl[i] != 0 && tbl[i] & Present_bit)
          {
            trace().printf("%i :: 0x%16llx\n", i, tbl[i]);
            dump_level(guest_phys(tbl[i] & _phys_addr_mask_4k));
          }
      }
    trace().printf(" +++++ Dumped all entries ++++ \n");
  }

  struct Level
  {
    Level(int s, l4_uint64_t m) : shift(s), mask(m) {}

    l4_uint64_t get_entry(l4_uint64_t *tbl, l4_uint64_t vaddr) const
    {
      trace().printf("next level idx: %llu\n", (vaddr & mask) >> shift);
      return tbl[(vaddr & mask) >> shift];
    }

    int const shift;
    l4_uint64_t const mask;
  };

  int max_physical_address_bit()
  {
      l4_umword_t ax, bx, cx, dx;
      // check for highest CPUID leaf:
      l4util_cpu_cpuid(0, &ax, &bx, &cx, &dx);
      trace().printf("CPUID max supported leaf 0x%lx\n", ax);
      if (ax == 0x80000008)
        {
          l4util_cpu_cpuid(0x80000008, &ax, &bx, &cx, &dx);
        }
      else
        {
          l4util_cpu_cpuid(0x1, &ax, &bx, &cx, &dx);
          if (dx & (1UL << 6)) // PAE
            ax = 36; // minimum if leaf not supported
          else
            ax = 32;
        }
      trace().printf("Physical address width = 0x%lx\n", ax);
      return ax & Max_phys_addr_bits_mask;
  }

  static Dbg trace() { return Dbg(Dbg::Core, Dbg::Trace); }

  enum
  {
    Table_index_size = 9,
    Table_index_mask = (1UL << Table_index_size) - 1,

    K4_offset_size = 12,
    K4_offset_mask = (1UL << K4_offset_size) - 1,

    M2_offset_size = 21,
    M2_offset_mask = (1UL << M2_offset_size) - 1,

    G1_offset_size = 30,
    G1_offset_mask = (1UL << G1_offset_size) - 1,

    Pt_shift = 12,
    Pt_mask = Table_index_mask << Pt_shift,

    Pd_shift = 21,
    Pd_mask = Table_index_mask << Pd_shift,

    Pdpt_shift = 30,
    Pdpt_mask = Table_index_mask << Pdpt_shift,

    Pml4_shift = 39,
    Pml4_mask = Table_index_mask << Pml4_shift,

    Present_bit = 1UL,
    RW_bit = 2UL,
    US_bit = 4UL,
    Pagesize_bit = 1UL << 7,

    Phys_addr_4k = 12,
    Phys_addr_2m = 21,
    Phys_addr_1g = 30,

    XD_bit_shift = 63,
    XD_bit = 1UL << XD_bit_shift,

    Pt_levels = 4,
    Max_phys_addr_bits_mask = 0xff,
  };

  Vm_mem const *_mmap;
  Level const _levels[Pt_levels];
  l4_uint64_t _phys_addr_mask_4k;
  l4_uint64_t _phys_addr_mask_2m;
  l4_uint64_t _phys_addr_mask_1g;
  l4_addr_t cached_start, cached_end, cached_ds_local_start;
};

} // namespace Vmm
