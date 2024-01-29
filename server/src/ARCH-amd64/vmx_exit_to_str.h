/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

namespace Vmm {

static const char *str_exit_reason[] =
{
  /*  0 */ "Exception or NMI",
  /*  1 */ "External interrupt",
  /*  2 */ "Triple fault",
  /*  3 */ "INIT signal",
  /*  4 */ "Start-up IPI",
  /*  5 */ "I/O system-management interrupt",
  /*  6 */ "Other SMI",
  /*  7 */ "Interrupt window",
  /*  8 */ "NMI window",
  /*  9 */ "Task switch",
  /* 10 */ "CPUID instruction",
  /* 11 */ "GETSEC instruction",
  /* 12 */ "HLT instruction",
  /* 13 */ "INVD instruction",
  /* 14 */ "INVLPG instruction",
  /* 15 */ "RDPMC instruction",
  /* 16 */ "RDTSC instruction",
  /* 17 */ "RSM instruction",
  /* 18 */ "VMCALL instruction",
  /* 19 */ "VMCLEAR instruction",
  /* 20 */ "VMLAUNCH instruction",
  /* 21 */ "VMPTRLD instruction",
  /* 22 */ "VMPTRST instruction",
  /* 23 */ "VMREAD instruction",
  /* 24 */ "VMRESUME instruction",
  /* 25 */ "VMWRITE instruction",
  /* 26 */ "VMXOFF instruction",
  /* 27 */ "VMXON instruction",
  /* 28 */ "Control-register accesses",
  /* 29 */ "MOV DR",
  /* 30 */ "I/O instruction",
  /* 31 */ "RDMSR instruction",
  /* 32 */ "WRMSR instruction",
  /* 33 */ "VM-entry failure due to invalid guest state",
  /* 34 */ "VM-entry failure due to MSR loading",
  /* 35 */ "",
  /* 36 */ "MWAIT instruction",
  /* 37 */ "Monitor trap flag",
  /* 38 */ "",
  /* 39 */ "MONITOR instruction",
  /* 40 */ "PAUSE instruction",
  /* 41 */ "VM-entry failure due to machine-check event",
  /* 42 */ "",
  /* 43 */ "TPR below threshold",
  /* 44 */ "APIC access",
  /* 45 */ "Virtualized EOI",
  /* 46 */ "Access to GDTR or IDTR",
  /* 47 */ "Access to LDTR or TR",
  /* 48 */ "EPT violation",
  /* 49 */ "EPT misconfiguration",
  /* 50 */ "INVEPT instruction",
  /* 51 */ "RDTSCP instruction",
  /* 52 */ "VMX-preemption timer expired",
  /* 53 */ "INVVPID instruction",
  /* 54 */ "WBINVD instruction",
  /* 55 */ "XSETBV instruction",
  /* 56 */ "APIC write",
  /* 57 */ "RDRAND instruction",
  /* 58 */ "INVPCID instruction",
  /* 59 */ "VM function invoked",
  /* 60 */ "ENCLS instruction",
  /* 61 */ "RDSEED instruction",
  /* 62 */ "Page-modification log full event",
  /* 63 */ "XSAVES instruction",
  /* 64 */ "XRSTORS instruction",
  /* 65 */ "",
  /* 66 */ "SPP-related event",
  /* 67 */ "UMWAIT instruction",
  /* 68 */ "TPAUSE instruction",
  /* 69 */ "LOADIWKEY instruction"
};

// Returns a human readable string for any given exit reason.
inline char const *exit_reason_to_str(l4_uint64_t exit_reason)
{
  if (exit_reason < (sizeof(str_exit_reason) / sizeof(char const *)))
    return str_exit_reason[exit_reason];
  return "Unknown";
}

} // namespace Vmm
