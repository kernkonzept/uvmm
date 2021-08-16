/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <cassert>

#include <l4/sys/vm.h>

#include "generic_vcpu_ptr.h"
#include "mem_access.h"
#include "riscv_arch.h"
#include "riscv_instruction.h"

namespace Vmm {

class Vcpu_ptr : public Generic_vcpu_ptr
{
public:
  explicit Vcpu_ptr(l4_vcpu_state_t *s) : Generic_vcpu_ptr(s) {}

  bool operator == (Vcpu_ptr const &other) const
  { return _s == other._s; }

  bool operator != (Vcpu_ptr const &other) const
  { return !operator==(other); }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
  }

  bool pf_write() const
  {
    return _s->r.cause == Riscv::Exc_guest_store_page_fault;
  }

  void jump_instruction(unsigned inst_size)
  {
    _s->r.ip += inst_size;
  }

  void jump_trap_instruction()
  {
    Riscv::Instruction insn(vm_state()->htinst);
    jump_instruction(insn.inst_size());
  }

  void jump_system_instruction()
  {
    jump_instruction(4);
  }

  Mem_access decode_mmio() const
  {
    Riscv::Instruction insn(vm_state()->htinst);
    Mem_access m;

    if (insn.is_load())
      {
        m.access = Mem_access::Load;
        m.width = insn.load_store_width();
      }
    else if(insn.is_store())
      {
        m.access = Mem_access::Store;
        m.width = insn.load_store_width();
        m.value = reg_read(insn.rs2());
      }
    else
      m.access = Mem_access::Other;

    return m;
  }

  void writeback_mmio(Mem_access const &m)
  {
    assert(m.access == Mem_access::Load);

    Riscv::Instruction insn(vm_state()->htinst);
    if(insn.is_load())
      reg_write(insn.rd(),
                reg_extend_width(m.value, m.width, !insn.is_unsigned_load()));
  }

  l4_vm_state_t *vm_state() const
  { return l4_vm_state(_s); }

  bool has_pending_irq()
  {
    // At least one interrupt is enabled and pending
    return vm_state()->hie & vm_state()->hvip;
  }

private:
  l4_umword_t reg_read(l4_uint32_t reg) const
  {
    assert(reg < 32);
    // x0: zero register
    if (reg != 0)
      return _s->r.r[reg - 1];
    else
      return 0;
  }

  void reg_write(l4_uint32_t reg, l4_umword_t value)
  {
    assert(reg < 32);
    if (reg != 0)
      _s->r.r[reg - 1] = value;
  }
};

} // namespace
