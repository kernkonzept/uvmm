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
 "  .fpu neon                     \n"  // be able to access d16-d31
 "  mov    r6, sp                 \n"  // r6: save sp
 "  bic    sp, #7                 \n"
 "  sub    sp, sp, #(16 + 32*8)   \n"  // Why is there a gap of 16 bytes?
                                       // 32 double precision registers, 8 bytes
 "  mrc    p15, 0, r7, c1, c0, 2  \n"  // r7: save CPACR
 "  orr    r8, r7, #0x500000      \n"  // enable cp12+cp13 for PL1
 "  mcr    p15, 0, r8, c1, c0, 2  \n"
 "  vmrs   r8, fpexc              \n"  // r8: save FPEXC
 "  orr    r9, r8, #(1<<30)       \n"  // enable SIMD+FP
 "  vmsr   fpexc, r9              \n"
 "  movw   r9, #:lower16:save_32r \n"
 "  movt   r9, #:upper16:save_32r \n"
 "  ldr    r9, [r9]               \n"  // r9: 0: don't save; 1: save d16-d31
 "  add    r10, sp, #(16 + 0*8)   \n"  // r10: address of d0-d15
 "  vstm   r10, {d0-d15}          \n"
 "  cmp    r9, #0                 \n"
 "  beq    1f                     \n"
 "  add    r11, sp, #(16 + 16*8)  \n"  // r11: address of d16-d31
 "  vstm   r11, {d16-d31}         \n"
 "1:                              \n"
 "  mov    r4, r0                 \n"  // r4: save r0
 "  mrc    p15, 0, r5, c13, c0, 2 \n"  // r5: save TPIDRURW
 "  ldr    r2, [r0, #0x240]       \n"  // l4_vcpu_e_info_user()[0]
 "  ldr    r3, [r0, #0x24]        \n"  // vcpu->r.err
 "  mcr    p15, 0, r2, c13, c0, 2 \n"
 "  lsr    r3, r3, #24            \n"
 "  bic    r3, r3, #3             \n"
 "  movw   r12, #:lower16:vcpu_entries      \n"
 "  movt   r12, #:upper16:vcpu_entries      \n"
 "  add    r12, r12, r3           \n"
 "  ldr    r12, [r12]             \n"
 "  blx    r12                    \n"
 "  mov    r0, r4                 \n"
 "  bl     prepare_guest_entry    \n"
 "  vldm   r10, {d0-d15}          \n"  // restore d0-d15 (always)
 "  cmp    r9, #0                 \n"
 "  beq    1f                     \n"
 "  vldm   r11, {d16-d31}         \n"  // restore d16-d31 (on save_r32 = 1)
 "1:                              \n"
 "  vmsr   fpexc, r8              \n"  // restore FPEXC from r8
 "  mcr    p15, 0, r7, c1, c0, 2  \n"  // restore CPACR from r7
 "  movw   r2, #0xf803            \n"
 "  movt   r2, #0xffff            \n"
 "  mov    r3, #0                 \n"
 "  mov    sp, r6                 \n"  // restore sp from r6
 "  mcr    p15, 0, r5, c13, c0, 2 \n"  // restore TPIDRURW from r5
 "  mvn    pc, #" L4_stringify(~(L4_SYSCALL_INVOKE)) " \n"
 "                                \n"
 ".Lsave_32r:                     \n"
 "  .long save_32r                \n"
);

