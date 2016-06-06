/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/util/cap_alloc>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/sys/cache.h>
#include <l4/util/util.h>

#include "mmio_device.h"
#include "debug.h"
#include "vcpu.h"
#include "mips_instructions.h"

static Dbg mmio_msg(Dbg::Mmio, "mmio");

namespace Vmm {

template<typename T>
struct Mmio_device_t : Mmio_device
{
  bool access(l4_addr_t pfa, l4_addr_t offset, Cpu vcpu,
              L4::Cap<L4::Task>, l4_addr_t, l4_addr_t)
  {
    Mips::Instruction insn(vcpu->r.bad_instr);
    if (0)
      Dbg().printf("MMIO access @ 0x%lx (0x%lx) %s %u byte, instr: 0x%lx\n",
                   pfa, offset, insn.op_mem_store() ? "STORE" : "LOAD",
                   (unsigned) insn.op_mem_width(), vcpu->r.bad_instr);

    if (insn.is_simple_load_store())
      {
        if (insn.op_mem_store())
          {
            dev()->write(offset, insn.op_mem_width(), vcpu->r.r[insn.rt()],
                         vcpu.get_vcpu_id());
          }
        else
          {
            l4_uint32_t value = dev()->read(offset, insn.op_mem_width(),
                                            vcpu.get_vcpu_id());

            switch (insn.op_mem_width())
              {
              case 0:
                if (insn.op_mem_unsigned())
                  value = (l4_uint32_t) ((l4_uint8_t) value);
                else
                  value = (l4_int32_t) ((l4_int8_t) value);
                break;
              case 1:
                if (insn.op_mem_unsigned())
                  value = (l4_uint32_t) ((l4_uint16_t) value);
                else
                  value = (l4_int32_t) ((l4_int16_t) value);
                break;
              }

            vcpu->r.r[insn.rt()] = value;
          }
      }
    else
      return false;

    vcpu.jump_instruction();
    return true;
  }

private:
  T *dev()
  { return static_cast<T *>(this); }
};


template<typename BASE, typename T>
struct Read_mapped_mmio_device_t : Mmio_device
{
  Read_mapped_mmio_device_t(l4_size_t size)
  : _ds(L4Re::chkcap(L4Re::Util::make_auto_del_cap<L4Re::Dataspace>()))
  {
    auto *e = L4Re::Env::env();
    L4Re::chksys(e->mem_alloc()->alloc(size, _ds.get()));
    L4Re::chksys(e->rm()->attach(&_mmio_region, size,
                                 L4Re::Rm::Search_addr
                                 | L4Re::Rm::Cache_uncached,
                                 L4::Ipc::make_cap_rw(_ds.get())));
  }

  bool access(l4_addr_t pfa, l4_addr_t offset, Cpu vcpu,
              L4::Cap<L4::Task> vm_task, l4_addr_t min, l4_addr_t max)
  {
    Mips::Instruction insn(vcpu->r.bad_instr);

    if (!insn.is_simple_load_store())
      return false;

    if (insn.op_mem_store())
      {
        dev()->write(offset, insn.op_mem_width(), vcpu->r.r[insn.rt()],
                     vcpu.get_vcpu_id());
      }
    else
      {
        map_mmio(pfa, offset, vm_task, min, max);

        l4_uint32_t value = dev()->read(offset, insn.op_mem_width(),
                                        vcpu.get_vcpu_id());

        switch (insn.op_mem_width())
          {
          case 0:
            if (insn.op_mem_unsigned())
              value = (l4_uint32_t) ((l4_uint8_t) value);
            else
              value = (l4_int32_t) ((l4_int8_t) value);
            break;
          case 1:
            if (insn.op_mem_unsigned())
              value = (l4_uint32_t) ((l4_uint16_t) value);
            else
              value = (l4_int32_t) ((l4_int16_t) value);
            break;
          }

        vcpu->r.r[insn.rt()] = value;
      }

    vcpu.jump_instruction();
    return true;
  }

  void map_mmio(l4_addr_t pfa, l4_addr_t offset, L4::Cap<L4::Task> vm_task,
                l4_addr_t min, l4_addr_t max)
  {
    unsigned char ps = L4_PAGESHIFT;

    if (l4_trunc_size(pfa, L4_SUPERPAGESHIFT) >= min
        && l4_round_size(pfa, L4_SUPERPAGESHIFT) <= max)
      ps = L4_SUPERPAGESHIFT;

    // XXX make sure that the page is currently mapped
    l4_addr_t base = l4_trunc_size(local_addr() + offset, ps);
    l4_touch_ro((void *)base, 1 << ps);

    auto res = vm_task->map(L4Re::This_task,
                            l4_fpage(base, ps, L4_FPAGE_RX),
                            l4_trunc_size(pfa, ps));

    if (l4_error(res) < 0)
      Err().printf("Could not map to mmio address %lx. Ignored.\n", pfa);
  }

private:
  BASE *dev()
  { return static_cast<BASE *>(this); }

  l4_addr_t local_addr() const
  { return reinterpret_cast<l4_addr_t>(_mmio_region.get()); }

  L4Re::Util::Auto_del_cap<L4Re::Dataspace>::Cap _ds;

protected:
  L4Re::Rm::Auto_region<T *> _mmio_region;
};

}
