/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/l4virtio/virtqueue>

#include "debug.h"
#include "ds_mmio_mapper.h"
#include "vcpu_ptr.h"
#include "vm_memmap.h"

namespace Vmm {

class Pt_walker
{
public:
  Pt_walker(Vm_mem const *mmap, unsigned max_phys_addr_bit)
  : _mmap(mmap),
    _levels {{Pml4_shift, Pml4_mask},
             {Pdpt_shift, Pdpt_mask},
             {Pd_shift, Pd_mask},
             {Pt_shift, Pt_mask}
            },
    cached_start(-1),
    cached_end(0),
    cached_ds_local_start(0),
    _max_phys_addr_mask((1UL << max_phys_addr_bit) - 1)
  {
    trace().printf("PT_walker: MAXPHYSADDR bits %i\n", max_phys_addr_bit);

    _phys_addr_mask_4k = _max_phys_addr_mask & ~((1UL << Phys_addr_4k) - 1);
    _phys_addr_mask_2m = _max_phys_addr_mask & ~((1UL << Phys_addr_2m) - 1);
    _phys_addr_mask_1g = _max_phys_addr_mask & ~((1UL << Phys_addr_1g) - 1);
  }

  l4_uint64_t walk(Vcpu_ptr vcpu, l4_uint64_t virt_addr)
  {
    l4_uint64_t cr3 = vcpu.vm_state()->cr3();

    trace().printf("cr3 0x%llx\n", cr3);

    // cr3 alignment check -- ignore bits 3 PWT, 4 PCD
    if (cr3 & (~_max_phys_addr_mask | 0xfe7))
      L4Re::chksys(-L4_EINVAL, "CR3 address is 4k aligned.");

    l4_uint64_t *tbl = translate_to_table_base(cr3 & ~0x18);
    l4_uint64_t entry = _levels[0].get_entry(tbl, virt_addr);

    trace().printf("cr3 0x%llx, entry 0x%llx, vaddr 0x%llx\n", cr3, entry,
                   virt_addr);

    if (!(entry & Present_bit))
      L4Re::chksys(-L4_EINVAL, "PML4 table is present\n");

    for (unsigned i = 1; i < Pt_levels; ++i)
      {
        // PML4Entry: no PAT bit (12) --> mask everything except [M-1:12]
        tbl = translate_to_table_base(entry & _phys_addr_mask_4k);
        entry = _levels[i].get_entry(tbl, virt_addr);

        if (!(entry & Present_bit))
          {
            Err().printf("Entry not present 0x%llx\n", entry);
            L4Re::chksys(-L4_EINVAL, "Found entry is present.\n");
          }

        // check for PS = 0 in PDPT & PD entries
        if (i < 3 && entry & Pagesize_bit)
          {
            if (i == 1)
              return add_voffset(translate_to_table_base(entry & _phys_addr_mask_1g),
                                 virt_addr & G1_offset_mask);
            if (i == 2)
              return add_voffset(translate_to_table_base(entry & _phys_addr_mask_2m),
                                 virt_addr & M2_offset_mask);
          }
      }

    return add_voffset(translate_to_table_base(entry & _phys_addr_mask_4k),
                       virt_addr & K4_offset_mask);
  }

private:
  Vm_mem::value_type const *addr_to_mem(Vmm::Guest_addr addr) const
  {
    Vm_mem::const_iterator f = _mmap->find(Region(addr));
    if (f == _mmap->end())
      {
        Dbg().printf("Fail: 0x%lx memory not found.\n", addr.get());
        L4Re::chksys(-L4_EINVAL,
                     "Memory used in page table walk is registered.");
      }
    if (f->first.type != Vmm::Region_type::Ram)
      {
        Dbg().printf("Fail: 0x%lx region has invalid type %d.\n", addr.get(),
                     static_cast<int>(f->first.type));
        L4Re::chksys(-L4_EINVAL,
                     "Address used in page table walk references RAM.");
      }

    return &*f;
  }

  Ds_handler const *mem_to_ds(Vm_mem::value_type const *mem) const
  {
    Ds_handler const *ds = dynamic_cast<Ds_handler *>(mem->second.get());
    if (!ds)
      L4Re::chksys(-L4_EINVAL,
                   "Dataspace handler for page table memory registered\n");

    return ds;
  }

  l4_uint64_t *translate_to_table_base(l4_uint64_t addr)
  {
    Vmm::Guest_addr ga(addr);
    if (cached_start.get() == -1U || cached_start > ga || cached_end < ga)
      {
        auto const *cached_mem = addr_to_mem(ga);
        cached_start = cached_mem->first.start;
        cached_end = cached_mem->first.end;
        cached_ds_local_start = mem_to_ds(cached_mem)->local_start();
      }

    if (ga + 512 * 8 > cached_end)
      L4Re::chksys(-L4_EINVAL, "Page-table end within guest memory\n");

    auto *ret = reinterpret_cast<l4_uint64_t *>(
                  cached_ds_local_start + (ga - cached_start));
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
            dump_level(translate_to_table_base(tbl[i] & _phys_addr_mask_4k));
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
  };

  Vm_mem const *_mmap;
  Level const _levels[Pt_levels];
  l4_uint64_t _phys_addr_mask_4k;
  l4_uint64_t _phys_addr_mask_2m;
  l4_uint64_t _phys_addr_mask_1g;
  Vmm::Guest_addr cached_start, cached_end;
  l4_addr_t cached_ds_local_start;
  l4_uint64_t _max_phys_addr_mask;
};

} // namespace Vmm
