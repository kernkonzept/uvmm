/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#pragma once

asm
(
 "vcpu_entry:                     \n"
 "  mov    x19, sp                \n"
 "  mrs    x20, TPIDR_EL0         \n"
 "  mov    x21, x0                \n"
 "  bic    x7, x19, #0xf          \n"
 "  mov    sp, x7                 \n"
 "  ldr    x8, [x0, #0x208]       \n"  // L4_VCPU_OFFSET_EXT_INFOS + 8
 "  ldr    w9, [x0, #0x148]       \n"  // vcpu->r.err
 "  msr    TPIDR_EL0, x8          \n"
 "  lsr    x9, x9, #23            \n"
 "  bic    x9, x9, #7             \n"
 "  adr    x10, vcpu_entries      \n"
 "  add    x10, x10, x9           \n"
 "  ldr    x11, [x10]             \n"
 "  blr    x11                    \n"
 "  mov    x0, x21                \n"
 "  bl     prepare_guest_entry    \n"
 "  mov    x2, #0xfffffffffffff803\n"
 "  mov    x3, #0                 \n"
 "  msr    TPIDR_EL0, x20         \n"
 "  mov    sp, x19                \n"
 "  svc    #0                     \n"
);

namespace Vmm {

enum { Guest_64bit_supported = true };

static void
dump(Vcpu_ptr vcpu)
{
  for (unsigned i = 0; i < 31; ++i)
    printf("x%2d:%16lx%s", i, vcpu->r.r[i], (i % 4) == 3 ? "\n" : "  ");

  printf("\n");
  printf("pc=%lx  sp=%lx  psr=%lx  sctlr=%x\n",
         vcpu->r.ip, vcpu->r.sp, vcpu->r.flags,
         vcpu.state()->vm_regs.sctlr);
}

inline void
print_mrs_msr(Vcpu_ptr vcpu, Vmm::Arm::Hsr hsr)
{
  if (hsr.msr_read())
    printf("%08lx: mrs x%d, S%d_%d_C%d_C%d_%d\n",
           vcpu->r.ip, (unsigned)hsr.msr_rt(),
           (unsigned)hsr.msr_op0(),
           (unsigned)hsr.msr_op1(),
           (unsigned)hsr.msr_crn(),
           (unsigned)hsr.msr_crm(),
           (unsigned)hsr.msr_op2());
  else
    printf("%08lx: msr S%d_%d_C%d_C%d_%d, %d=%lx\n",
           vcpu->r.ip,
           (unsigned)hsr.msr_op0(),
           (unsigned)hsr.msr_op1(),
           (unsigned)hsr.msr_crn(),
           (unsigned)hsr.msr_crm(),
           (unsigned)hsr.msr_op2(),
           (unsigned)hsr.msr_rt(),
           vcpu->r.r[hsr.msr_rt()]);
  dump(vcpu);
}

static void guest_msr_access(Vcpu_ptr vcpu)
{
  auto hsr = vcpu.hsr();
  switch (hsr.msr_sysreg())
    {
    case Vmm::Arm::Hsr::msr_sysreg(2, 3, 0, 5, 0): // DBGDTRTX/RX_EL0
      if (hsr.msr_read())
        vcpu.set_gpr(hsr.msr_rt(), 0);
      else
        putchar(vcpu.get_gpr(hsr.mcr_rt()));
      break;

    case Vmm::Arm::Hsr::msr_sysreg(2, 3, 0, 1, 0): // MDCCSR_EL0
      if (hsr.msr_read())
        vcpu.set_gpr(hsr.msr_rt(), 0);
      break;

    default:
      if (0)
        print_mrs_msr(vcpu, hsr);
      break;
    }

  vcpu->r.ip += 2 << hsr.il();
}

}
