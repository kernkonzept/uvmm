/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#pragma once

namespace Vmm {

enum { Guest_64bit_supported = true };

static void
dump(Vcpu_ptr vcpu)
{
  for (unsigned i = 0; i < 31; ++i)
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("x%2d:%16lx%s", i, vcpu->r.r[i], (i % 4) == 3 ? "\n" : "  ");

  Dbg(Dbg::Cpu, Dbg::Info)
    .printf("\n");
  Dbg(Dbg::Cpu, Dbg::Info)
    .printf("pc=%lx  sp=%lx  psr=%lx  sctlr=%x\n",
            vcpu->r.ip, vcpu->r.sp, vcpu->r.flags,
            l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR));
}

inline void
print_mrs_msr(Vcpu_ptr vcpu, Vmm::Arm::Hsr hsr)
{
  if (hsr.msr_read())
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("%08lx: mrs x%d, S%d_%d_C%d_C%d_%d\n",
              vcpu->r.ip, (unsigned)hsr.msr_rt(),
              (unsigned)hsr.msr_op0(),
              (unsigned)hsr.msr_op1(),
              (unsigned)hsr.msr_crn(),
              (unsigned)hsr.msr_crm(),
              (unsigned)hsr.msr_op2());
  else
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("%08lx: msr S%d_%d_C%d_C%d_%d, %d=%lx\n",
              vcpu->r.ip,
              (unsigned)hsr.msr_op0(),
              (unsigned)hsr.msr_op1(),
              (unsigned)hsr.msr_crn(),
              (unsigned)hsr.msr_crm(),
              (unsigned)hsr.msr_op2(),
              (unsigned)hsr.msr_rt(),
              vcpu.get_gpr(hsr.msr_rt()));
  dump(vcpu);
}

static void log_msr_access(const char *name, Vmm::Arm::Hsr hsr, Vcpu_ptr vcpu)
{
  if (hsr.msr_read())
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Unimplemented read access to %s at %lx\n",
              name, vcpu->r.ip);
  else
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Unimplemented write access to %s=%lx at %lx\n",
              name, vcpu.get_gpr(hsr.msr_rt()), vcpu->r.ip);
}

static void log_msr_access_n(const char *name, Vmm::Arm::Hsr hsr, Vcpu_ptr vcpu)
{
  if (hsr.msr_read())
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Unimplemented read access to %s[%d] at %lx\n",
              name, (int)hsr.msr_crm(), vcpu->r.ip);
  else
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Unimplemented write access to %s[%d]=%lx at %lx\n",
              name, (int)hsr.msr_crm(), vcpu.get_gpr(hsr.msr_rt()), vcpu->r.ip);
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
      else
        log_msr_access("MDCCSR_EL0", hsr, vcpu);
      break;

    case Vmm::Arm::Hsr::msr_sysreg(2, 0, 0, 2, 2): // MDSCR_EL1
      log_msr_access("MDSCR_EL1", hsr, vcpu);
      break;

    case Vmm::Arm::Hsr::msr_sysreg(3, 3, 9, 14, 0): // PMUSERENR_EL0
      log_msr_access("PMUSERENR_EL0", hsr, vcpu);
      break;

    default:
      switch (hsr.msr_sysreg_n())
        {
        case Vmm::Arm::Hsr::msr_sysreg_n(2, 0, 0, 4): // DBGBCR<n>_EL1
          log_msr_access_n("DBGBVR<n>_EL1", hsr, vcpu);
          break;

        case Vmm::Arm::Hsr::msr_sysreg_n(2, 0, 0, 5): // DBGBCR<n>_EL1
          log_msr_access_n("DBGBCR<n>_EL1", hsr, vcpu);
          break;

        case Vmm::Arm::Hsr::msr_sysreg_n(2, 0, 0, 6): // DBGWVR<n>_EL1
          log_msr_access_n("DBGWVR<n>_EL1", hsr, vcpu);
          break;

        case Vmm::Arm::Hsr::msr_sysreg_n(2, 0, 0, 7): // DBGWCR<n>_EL1
          log_msr_access_n("DBGWCR<n>_EL1", hsr, vcpu);
          break;

        default:
          print_mrs_msr(vcpu, hsr);
          break;
        }
      break;
    }

  vcpu->r.ip += 2 << hsr.il();
}

}
