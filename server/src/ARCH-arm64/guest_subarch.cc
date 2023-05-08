/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#include <l4/sys/thread.h>
#include <l4/re/elf_aux.h>
#include "guest.h"

L4RE_ELF_AUX_ELEM_T(l4re_elf_aux_mword_t, __ex_regs_flags,
                    L4RE_ELF_AUX_T_EX_REGS_FLAGS,
                    L4_THREAD_EX_REGS_ARM64_SET_EL_EL1);

asm (
  ".global __l4_sys_syscall\n"
  ".type __l4_sys_syscall, @function\n"
  "__l4_sys_syscall:\n"
  "   hvc #0\n"
  "   ret\n"
);

namespace Vmm {

void
Guest::add_sys_reg_aarch64(unsigned op0, unsigned op1,
                           unsigned crn, unsigned crm,
                           unsigned op2,
                           cxx::Ref_ptr<Vmm::Arm::Sys_reg> const &r)
{
  _sys_regs[Vmm::Arm::Sys_reg::Key::sr(op0, op1, crn, crm, op2)] = r;
}

}
