/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/compiler.h>

asm
(
 "vcpu_entry:                     \n"
 "  mov    r6, sp                 \n"
 "  bic    sp, #7                 \n"
 "  sub    sp, sp, #16            \n"
 "  mov    r4, r0                 \n"
 "  mrc    p15, 0, r5, c13, c0, 2 \n"
 "  ldr    r2, [r0, #0x200]       \n"  // L4_VCPU_OFFSET_EXT_INFOS
 "  ldr    r3, [r0, #0x24]        \n"  // vcpu->r.err
 "  mcr    p15, 0, r2, c13, c0, 2 \n"
 "  lsr    r3, r3, #24            \n"
 "  bic    r3, r3, #3             \n"
 "  movw   r8, #:lower16:vcpu_entries      \n"
 "  movt   r8, #:upper16:vcpu_entries      \n"
 "  add    r8, r8, r3             \n"
 "  ldr    r8, [r8]               \n"
 "  blx    r8                     \n"
 "  mov    r0, r4                 \n"
 "  bl     prepare_guest_entry    \n"
 "  movw   r2, #0xf803            \n"
 "  movt   r2, #0xffff            \n"
 "  mov    r3, #0                 \n"
 "  mov    sp, r6                 \n"
 "  mcr    p15, 0, r5, c13, c0, 2 \n"
 "  mov    pc, #" L4_stringify(L4_SYSCALL_INVOKE) " \n"
);
