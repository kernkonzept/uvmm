/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>
#include <cstring>

#include <l4/re/error_helper>
#include <l4/sys/kdebug.h>
#include <l4/sys/thread_mips.h>
#include <l4/sys/vm.h>

#include "generic_vcpu_ptr.h"
#include "mem_access.h"
#include "mips_instructions.h"

namespace Vmm {

struct Fpu_state
{
#if __mips_fpr == 64
  l4_uint64_t read(unsigned fpnr)
  { return regs[fpnr]; }

  void write(unsigned fpnr, char, l4_uint64_t value)
  { regs[fpnr] = value; }

  l4_uint64_t regs[32];
#else

  l4_uint64_t read(unsigned fpnr)
  {
    // registers are numbered by 32bit but saved in 64bit
    // so for odd FPU register numbers return the upper 32bits.
    return regs[fpnr >> 1] >> (32 * (fpnr & 1));
  }

  void write(unsigned fpnr, char size, l4_uint64_t value)
  {
    if (size == 3)
      regs[fpnr >> 1] = value;
    else
      {
        // write the 32bit value in the upper or lower part of the
        // saved 64bit value
        value &= 0xffffffff;
        // Mask for the 64bit register: upper 32 bit for even FPU registers,
        // lower 32 bit for odd FPU registers.
        l4_uint64_t regmask = (0xffffffffULL << (32 * (~fpnr & 1)));
        regs[fpnr >> 1] = (regmask & regs[fpnr >> 1])
                          | (value << (32 * (fpnr & 1)));
      }
  }

  l4_uint64_t regs[16];
#endif
  l4_umword_t status;
};

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

class Vcpu_ptr : public Generic_vcpu_ptr
{
public:
  explicit Vcpu_ptr(l4_vcpu_state_t *s) : Generic_vcpu_ptr(s) {}

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
        if (insn.rt() == 0)
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8; // R6 compact branch instruction
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
        if (insn.rt() == 0 && (long) r->r[insn.rs()] > 0)
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8;
        return;
      case Mips::Op::Blez:
        if (insn.rt() == 0 && (long) r->r[insn.rs()] <= 0)
          r->ip += insn.branch_offset() + 4;
        else
          r->ip += 8;
        return;
      case Mips::Op::Jal:
        r->ra = r->ip + 8;
        // fallthrough
      case Mips::Op::J:
        r->ip = (r->ip & ~((1UL << 28) - 1)) | (insn.instr_index() << 2);
        return;
      // compact branch instructions on R6
      case Mips::Op::Pop10:
      case Mips::Op::Pop30:
      case Mips::Op::Pop66:
      case Mips::Op::Pop76:
          r->ip += 8;
          return;
      }

    Err().printf("Guest exception in branch delay slot. Instruction not implemented @ IP 0x%lx\n", _s->r.ip);
    enter_kdebug("STOP");
  }

  Mem_access decode_mmio() const
  {
    Mips::Instruction insn(_s->r.bad_instr);
    Mem_access m;

    m.access = insn.op_mem_store() ? Mem_access::Store : Mem_access::Load;

    if (insn.is_simple_load_store())
      {
        m.width = insn.load_store_width();

        if (m.access == Mem_access::Store)
          m.value = _s->r.r[insn.rt()];
      }
    else if (insn.is_fp_load_store())
      {
        m.width = insn.op_fp_dc1() ? Mem_access::Wd64 : Mem_access::Wd32;

        if (m.access == Mem_access::Store)
          m.value = fpu_state()->read(insn.rt());
      }
    else
      m.access = Mem_access::Other;

    return m;
  }

  void writeback_mmio(Mem_access const &m) const
  {
    assert(m.access == Mem_access::Load);

    Mips::Instruction insn(_s->r.bad_instr);

    if (insn.is_simple_load_store())
      _s->r.r[insn.rt()]
        = reg_extend_width(m.value, m.width, insn.op_mem_unsigned());
    else
      fpu_state()->write(insn.rt(), m.width, m.value);
  }

  Fpu_state *fpu_state() const
  { return reinterpret_cast<Fpu_state *>(_s->user_data[Reg_fpu_state]); }

  void alloc_fpu_state() const
  {
    _s->user_data[Reg_fpu_state]
      = reinterpret_cast<l4_umword_t>(new Fpu_state());
  }

  void free_fpu_state() const
  {
    if (fpu_state())
      {
        delete fpu_state();
        _s->user_data[Reg_fpu_state] = 0;
      }
  }

  l4_umword_t proc_id() const
  { return _s->user_data[Reg_proc_id]; }

  void set_proc_id(l4_umword_t id) const
  { _s->user_data[Reg_proc_id] = id; }

  State *state()
  { return reinterpret_cast<State *>((char *)_s + L4_VCPU_OFFSET_EXT_STATE); }

private:
  enum Arch_data_regs {
      Reg_fpu_state = Reg_arch_base,
      Reg_proc_id,
      Reg_arch_end
  };

  static_assert(Reg_arch_end <= 7, "Too many user_data registers used");
};

} // namespace
