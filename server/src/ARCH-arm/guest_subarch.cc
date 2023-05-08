/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017, 2020, 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#include <l4/sys/thread.h>
#include <l4/re/elf_aux.h>
#include "guest.h"

L4RE_ELF_AUX_ELEM_T(l4re_elf_aux_mword_t, __ex_regs_flags,
                    L4RE_ELF_AUX_T_EX_REGS_FLAGS,
                    L4_THREAD_EX_REGS_ARM_SET_EL_EL1);

namespace Vmm {

void
Guest::add_sys_reg_aarch64(unsigned, unsigned,
                           unsigned, unsigned,
                           unsigned,
                           cxx::Ref_ptr<Vmm::Arm::Sys_reg> const &)
{}

}
