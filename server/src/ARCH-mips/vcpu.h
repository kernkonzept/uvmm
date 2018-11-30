/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/error_helper>
#include <l4/sys/kdebug.h>
#include <l4/sys/thread_mips.h>
#include <l4/sys/vm.h>

#include "generic_vcpu.h"
#include "mips_instructions.h"

namespace Vmm {

struct State : l4_vm_state_t
{
  void set_modified(l4_umword_t bits)
  { modified_cp0_map |= bits; }

  void get_state(l4_umword_t bits)
  {
    if ((clean_cp0_map & bits) != bits)
      l4_thread_mips_save_vm_state(L4_INVALID_CAP, bits);
  }

  void update_state(l4_umword_t bits)
  { l4_thread_mips_save_vm_state(L4_INVALID_CAP, bits); }
};

class Cpu : public Generic_cpu
{
public:
  explicit Cpu(l4_vcpu_state_t *s) : Generic_cpu(s) {}

  bool pf_write() const
  { return _s->r.cause & 4; }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
  }

  void jump_instruction()
  {
    auto *r = &_s->r;
    if (!(r->cause & (1 << 31)))
      {
        r->ip += 4;
        return;
      }

    // emulate the branch instruction
    Mips::Instruction insn(r->bad_instr_p);

    switch (insn.opcode())
      {
      case Mips::Op::Special:
        switch (insn.func())
          {
          case Mips::Op::Sp_jr:
            r->ip = r->r[insn.rs()];
            return;
          case Mips::Op::Sp_jalr:
            auto ra = r->ip + 8;
            r->ip = r->r[insn.rs()];
            r->r[insn.rd()] = ra;
            return;
          }
        break;
      case Mips::Op::Regimm:
        switch (insn.rt())
          {
          case Mips::Op::Bal:
          case Mips::Op::Bgezall:
            r->r[31] = r->ip + 8;
          case Mips::Op::Bgez:
          case Mips::Op::Bgezl:
            if ((long) r->r[insn.rs()] >= 0)
              r->ip += insn.branch_offset() + 4;
            else
              r->ip += 8;
            return;
          case Mips::Op::Nal:
          case Mips::Op::Bltzall:
            r->r[31] = r->ip + 8;
          case Mips::Op::Bltz:
          case Mips::Op::Bltzl:
            if ((long) r->r[insn.rs()] < 0)
              r->ip += insn.branch_offset() + 4;
            else
              r->ip += 8;
            return;
          }
        break;
      case Mips::Op::Beql:
      case Mips::Op::Bnel:
      case Mips::Op::Bgtzl:
      case Mips::Op::Blezl:
        r->ip += insn.branch_offset() + 4;
        return;
      case Mips::Op::Beq:
        if (r->r[insn.rs()] == r->r[insn.rt()])
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8;
        return;
      case Mips::Op::Bne:
        if (r->r[insn.rs()] != r->r[insn.rt()])
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8;
        return;
      case Mips::Op::Bgtz:
        if ((long) r->r[insn.rs()] > 0)
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8;
        return;
      case Mips::Op::Blez:
        if ((long) r->r[insn.rs()] <= 0)
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8;
        return;
      case Mips::Op::Jal:
        r->ra = r->ip + 8;
      case Mips::Op::J:
        r->ip = (r->ip & ~((1UL << 28) - 1)) | (insn.instr_index() << 2);
        return;
      }

    Err().printf("Guest exception in branch delay slot. Instruction not implemented @ IP 0x%lx\n", _s->r.ip);
    enter_kdebug("STOP");
  }

  unsigned get_vcpu_id() const
  { return 0; } // TODO implement

  State *state()
  { return reinterpret_cast<State *>((char *)_s + L4_VCPU_OFFSET_EXT_STATE); }

};

} // namespace
