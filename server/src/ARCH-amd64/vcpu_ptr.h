/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include "generic_vcpu_ptr.h"
#include "mem_access.h"
#include "vm_state.h"

namespace Vmm {

class Pt_walker;

class Vcpu_ptr : public Generic_vcpu_ptr
{
public:
  enum User_data_regs_arch
  {
    Reg_vmm_type = Reg_arch_base,
    Reg_mmio_read,
    // <insert further register usage here>
    Reg_must_be_last_before_ucode,
    Reg_ucode_rev = 6, // must be in sync with Fiasco
  };
  static_assert(Reg_ucode_rev >= Reg_must_be_last_before_ucode,
                "Last user data register is reserved for microcode revision.");

  explicit Vcpu_ptr(l4_vcpu_state_t *s) : Generic_vcpu_ptr(s)
  {
    if (s)
      create_state(determine_vmm_type());
  }

  bool pf_write() const
  {
    return vm_state()->pf_write();
  }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
  }

  Vm_state *vm_state() const
  { return reinterpret_cast<Vm_state *>(_s->user_data[Reg_vmm_type]);}

  Mem_access decode_mmio() const;

  void writeback_mmio(Mem_access const m)
  {
    // used to write read value back to register it is read to.
    *decode_reg_ptr(_s->user_data[Reg_mmio_read]) = m.value;
  }

  void reset(bool protected_mode);
  void hot_reset();

  l4_umword_t ucode_revision() const
  { return _s->user_data[Reg_ucode_rev]; }

  template <typename ERR_DBG>
  void dump_regs_t(l4_addr_t vm_ip, ERR_DBG out) const
  {
    unsigned vcpu_id = get_vcpu_id();
    l4_vcpu_regs_t *regs = &_s->r;

    out.printf("[%3u] RAX 0x%lx\nRBX 0x%lx\nRCX 0x%lx\nRDX 0x%lx\nRSI 0x%lx\n"
               "RDI 0x%lx\nRSP 0x%lx\nRBP 0x%lx\nR8 0x%lx\nR9 0x%lx\n"
               "R10 0x%lx\nR11 0x%lx\nR12 0x%lx\nR13 0x%lx\nR14 0x%lx\n"
               "R15 0x%lx\nRIP 0x%lx\nvCPU RIP 0x%lx\n",
               vcpu_id, regs->ax, regs->bx, regs->cx, regs->dx, regs->si,
               regs->di, regs->sp, regs->bp, regs->r8, regs->r9, regs->r10,
               regs->r11, regs->r12, regs->r13, regs->r14, regs->r15, vm_ip,
               regs->ip);
  }

private:
  void *extended_state() const
  {
    return (void *)(((char *)_s) + L4_VCPU_OFFSET_EXT_STATE);
  }

  Vm_state::Type determine_vmm_type();
  void create_state(Vm_state::Type type);
  l4_umword_t *decode_reg_ptr(int value) const;

}; // class Vcpu_ptr

} // namespace Vmm

