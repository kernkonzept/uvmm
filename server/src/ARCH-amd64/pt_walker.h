/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/l4virtio/virtqueue>
#include <l4/cxx/ref_ptr>

#include "debug.h"
#include "ds_mmio_mapper.h"
#include "vcpu_ptr.h"
#include "vm_ram.h"

namespace Vmm {

class Pt_walker : public cxx::Ref_obj
{
public:
  Pt_walker(cxx::Ref_ptr<Vm_ram> mmap, unsigned max_phys_addr_bit)
  : _mmap(mmap),
    _levels {{Pml4_shift, Pml4_mask},
             {Pdpt_shift, Pdpt_mask},
             {Pd_shift, Pd_mask},
             {Pt_shift, Pt_mask}
            },
    _max_phys_addr_mask((1UL << max_phys_addr_bit) - 1)
  {
    trace().printf("PT_walker: MAXPHYSADDR bits %i\n", max_phys_addr_bit);

    _phys_addr_mask_4k = _max_phys_addr_mask & ~((1UL << Phys_addr_4k) - 1);
    _phys_addr_mask_2m = _max_phys_addr_mask & ~((1UL << Phys_addr_2m) - 1);
    _phys_addr_mask_1g = _max_phys_addr_mask & ~((1UL << Phys_addr_1g) - 1);
  }

  l4_uint64_t walk(l4_uint64_t cr3, l4_uint64_t virt_addr)
  {
    // mask everything besides the 4K-aligned PML4 table address
    l4_uint64_t *tbl = translate_to_table_base(cr3 & _phys_addr_mask_4k);
    l4_uint64_t entry = _levels[0].get_entry(tbl, virt_addr);

    if (0)
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
            char buf[78];
            snprintf(buf, sizeof(buf),
                     "Found entry is present. Actual: Entry 0x%llx not "
                     "present.\n",
                     entry);

            L4Re::chksys(-L4_EINVAL, buf);
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
  l4_uint64_t *translate_to_table_base(l4_uint64_t addr)
  {
    auto *ret = _mmap->guest2host<l4_uint64_t *>(Guest_addr(addr));
    if (0)
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
      if (0)
        trace().printf("next level idx: %llu\n", (vaddr & mask) >> shift);
      return tbl[(vaddr & mask) >> shift];
    }

    int const shift;
    l4_uint64_t const mask;
  };

  static Dbg trace() { return Dbg(Dbg::Mmio, Dbg::Trace, "PTW"); }

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

  cxx::Ref_ptr<Vm_ram> _mmap;
  Level const _levels[Pt_levels];
  l4_uint64_t _phys_addr_mask_4k;
  l4_uint64_t _phys_addr_mask_2m;
  l4_uint64_t _phys_addr_mask_1g;
  l4_uint64_t _max_phys_addr_mask;
};

} // namespace Vmm
