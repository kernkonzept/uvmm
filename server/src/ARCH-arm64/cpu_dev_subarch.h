/*
 * Copyright (C) 2017, 2019-2021, 2023-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

extern "C" void vcpu_entry(l4_vcpu_state_t *vcpu);
asm
(
 "vcpu_entry:                     \n"
 "  mrs    x20, TPIDR_EL0         \n"
 "  mov    x21, x0                \n"
 "  ldr    x8, [x0, #0x248]         \n"  // l4_vcpu_e_info_user()[1]
 "  ldr    w9, [x0, #0x148]         \n"  // vcpu->r.err
 "  msr    TPIDR_EL0, x8            \n"
 "  lsr    x9, x9, #23              \n"
 "  bic    x9, x9, #7               \n"
#ifdef __PIC__
 "  adrp   x10, vcpu_entries        \n"
 "  add    x10, x10, :lo12:vcpu_entries\n"
#else
 "  ldr    x10, =vcpu_entries       \n"
#endif
 "  add    x10, x10, x9             \n"
 "  ldr    x11, [x10]               \n"
 "  blr    x11                      \n"
 "  mov    x0, x21                  \n"
 "  bl     prepare_guest_entry      \n" // sets MR[0] = L4_THREAD_VCPU_RESUME_OP
                                        // and tag(L4_PROTO_THREAD, 1, 0, 0)
 "  mov    x2, #0xfffffffffffff803  \n" // dest = L4_INVALID_CAP, flags = call
 "  mov    x3, #0                   \n" // timeout never

 "  msr    TPIDR_EL0, x20           \n"
 "  hvc    #0                       \n"
);

