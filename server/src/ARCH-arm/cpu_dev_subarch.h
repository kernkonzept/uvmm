/*
 * Copyright (C) 2017, 2019-2021 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/compiler.h>

extern "C" void vcpu_entry(l4_vcpu_state_t *vcpu);
asm
(
 "vcpu_entry:                     \n"
 "  mov    r4, r0                 \n"  // r4: save r0
 "  mrc    p15, 0, r5, c13, c0, 2 \n"  // r5: save TPIDRURW
 "  ldr    r2, [r0, #0x140]       \n"  // l4_vcpu_e_info_user()[0]
 "  ldr    r3, [r0, #0x24]        \n"  // vcpu->r.err
 "  mcr    p15, 0, r2, c13, c0, 2 \n"
 "  lsr    r3, r3, #24            \n"
 "  bic    r3, r3, #3             \n"
#ifdef __PIC__
 "  ldr    r12, 2f                \n" // load offset to vcpu_entries
 "1:add    r12, pc, r12           \n" // convert to absolute address
#else
 "  movw   r12, #:lower16:vcpu_entries      \n"
 "  movt   r12, #:upper16:vcpu_entries      \n"
#endif
 "  add    r12, r12, r3           \n"
 "  ldr    r12, [r12]             \n"
 "  blx    r12                    \n"
 "  mov    r0, r4                 \n"
 "  bl     prepare_guest_entry    \n"
 "  movw   r2, #0xf803            \n"
 "  movt   r2, #0xffff            \n"
 "  mov    r3, #0                 \n"
 "  mcr    p15, 0, r5, c13, c0, 2 \n"  // restore TPIDRURW from r5
 "  mov    r5, #" L4_stringify(L4_SYSCALL_INVOKE) " \n"
 "  hvc    #0                     \n"
 "                                \n"
#ifdef __PIC__
 "2: .word vcpu_entries - (1b + 8)\n"
#endif
);

