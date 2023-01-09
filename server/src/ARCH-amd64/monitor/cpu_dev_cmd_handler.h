/*
 * Copyright (C) 2019-2021, 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>

#include "vmcs.h"
#include "vcpu_ptr.h"
#include "vm_state_vmx.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Cpu_dev_cmd_handler {};

template<typename T>
class Cpu_dev_cmd_handler<true, T> : public Cmd
{
public:
  char const *help() const override
  { return "CPU state"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'cpu <i> regs': dump CPU registers\n"
               "* 'cpu <i> vmx': dump VMX state\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  { compl_req->complete(f, {"regs", "vmx"}); }

  void exec(FILE *f, Arglist *args) override
  {
    if (*args == "regs")
      show_regs(f);
    else if (*args == "vmx")
      show_vmx(f);
    else
      argument_error("Invalid subcommand");
  }

  void show_regs(FILE *f) const
  {
    auto regs = get_vcpu()->r;
    auto *vms = get_vcpu().vm_state();

    fprintf(f,
            "RAX %lx\nRBX %lx\nRCX %lx\nRDX %lx\nRSI %lx\nRDI %lx\n"
            "RSP %lx\nRBP %lx\nR8 %lx\nR9 %lx\nR10 %lx\nR11 %lx\n"
            "R12 %lx\nR13 %lx\nR14 %lx\nR15 %lx\nRIP %lx\n",
            regs.ax, regs.bx, regs.cx, regs.dx, regs.si, regs.di,
            regs.sp, regs.bp, regs.r8, regs.r9, regs.r10, regs.r11,
            regs.r12, regs.r13, regs.r14, regs.r15, vms->ip());
  }

  void show_vmx(FILE *f) const
  {
    Vmm::Vmx_state *vmx = dynamic_cast<Vmm::Vmx_state *>(get_vcpu().vm_state());

    if (!vmx)
      {
        fprintf(f, "Failed to read VMX state\n");
        return;
      }

    fprintf(f, "(C) VPID: 0x%llx\n",
            vmx->vmx_read(VMCS_VPID));
    fprintf(f, "(C) Int notification vector: 0x%llx\n",
            vmx->vmx_read(VMCS_PIR_NOTIFICATION_VECTOR));
    fprintf(f, "(C) EPTP index: 0x%llx\n",
            vmx->vmx_read(VMCS_EPTP_INDEX));
    fprintf(f, "(C) EPT pointer: 0x%llx\n",
            vmx->vmx_read(VMCS_EPT_POINTER));
    fprintf(f, "(C) Pin-based execution control: 0x%llx\n",
            vmx->vmx_read(VMCS_PIN_BASED_VM_EXEC_CTLS));
    fprintf(f, "(C) Primary execution control: 0x%llx\n",
            vmx->vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS));
    fprintf(f, "(C) Secondary execution control: 0x%llx\n",
            vmx->vmx_read(VMCS_SEC_PROC_BASED_VM_EXEC_CTLS));

    void *ext = static_cast<void *>(*get_vcpu());

    fprintf(f, "(c) basic capabilities: 0x%llx\n",
            l4_vm_vmx_get_caps(ext, L4_VM_VMX_BASIC_REG));
    fprintf(f, "(C) Real pin-based execution control: 0x%llx\n",
            l4_vm_vmx_get_caps(ext, L4_VM_VMX_TRUE_PINBASED_CTLS_REG));
    fprintf(f, "(C) Real primary execution control: 0x%llx\n",
            l4_vm_vmx_get_caps(ext, L4_VM_VMX_TRUE_PROCBASED_CTLS_REG));
    fprintf(f, "(C) Real secondary execution control: 0x%llx\n",
            l4_vm_vmx_get_caps(ext, L4_VM_VMX_PROCBASED_CTLS2_REG));

    fprintf(f, "(G) ES selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_ES_SELECTOR));
    fprintf(f, "(G) CS selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_CS_SELECTOR));
    fprintf(f, "(G) SS selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_SS_SELECTOR));
    fprintf(f, "(G) DS selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_DS_SELECTOR));
    fprintf(f, "(G) FS selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_FS_SELECTOR));
    fprintf(f, "(G) GS selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_GS_SELECTOR));
    fprintf(f, "(G) GDTR base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_GDTR_BASE));
    fprintf(f, "(G) IDTR base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_IDTR_BASE));

    fprintf(f, "(G) LDTR selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_LDTR_SELECTOR));
    fprintf(f, "(G) TR selector: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_TR_SELECTOR));
    fprintf(f, "(G) interrupt status: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_INTERRUPT_STATUS));

    fprintf(f, "(C) IO bitmap A: 0x%llx\n",
            vmx->vmx_read(VMCS_ADDRESS_IO_BITMAP_A));
    fprintf(f, "(C) IO bitmap B: 0x%llx\n",
            vmx->vmx_read(VMCS_ADDRESS_IO_BITMAP_B));
    fprintf(f, "(C) MSR bitmaps: 0x%llx\n",
            vmx->vmx_read(VMCS_ADDRESS_MSR_BITMAP));
    fprintf(f, "(C) Exit MSR store address: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_EXIT_MSR_STORE_ADDRESS));
    fprintf(f, "(C) Exit MSR load address: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_EXIT_MSR_LOAD_ADDRESS));
    fprintf(f, "(C) Entry MSR load address: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_ENTRY_MSR_LOAD_ADDRESS));

    fprintf(f, "(C) Entry control: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_ENTRY_CTLS));
    fprintf(f, "(C) Entry error: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_ENTRY_EXCEPTION_ERROR));
    fprintf(f, "(C) Entry MSR load cnt: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_ENTRY_MSR_LOAD_COUNT));
    fprintf(f, "(C) Entry interrupt info: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_ENTRY_INTERRUPT_INFO));
    fprintf(f, "(C) VM-instruction error: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_INSN_ERROR));
    fprintf(f, "(C) Exit control: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_EXIT_CTLS));
    fprintf(f, "(C) Exit reason: 0x%llx\n",
            vmx->vmx_read(VMCS_EXIT_REASON));
    fprintf(f, "(C) Exit interrupt info: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_EXIT_INTERRUPT_INFO));
    fprintf(f, "(C) Exit interrupt error: 0x%llx\n",
            vmx->vmx_read(VMCS_VM_EXIT_INTERRUPT_ERROR));
    fprintf(f, "(C) Guest interruptability: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_INTERRUPTIBILITY_STATE));

    fprintf(f, "(G) ES limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_ES_LIMIT));
    fprintf(f, "(G) CS limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_CS_LIMIT));
    fprintf(f, "(G) SS limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_SS_LIMIT));
    fprintf(f, "(G) DS limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_DS_LIMIT));
    fprintf(f, "(G) FS limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_FS_LIMIT));
    fprintf(f, "(G) GS limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_GS_LIMIT));
    fprintf(f, "(G) GDTR limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_GDTR_LIMIT));
    fprintf(f, "(G) IDTR limit: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_IDTR_LIMIT));
    fprintf(f, "(G) Activity state: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_ACTIVITY_STATE));

    fprintf(f, "(G) sysenter rip: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_IA32_SYSENTER_EIP));
    fprintf(f, "(G) sysenter rsp: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_IA32_SYSENTER_ESP));
    fprintf(f, "(G) exit qualification: 0x%llx\n",
            vmx->vmx_read(VMCS_EXIT_QUALIFICATION));
    fprintf(f, "(G) guest linear address: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_LINEAR_ADDRESS));
    fprintf(f, "(G) CR0: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_CR0));
    fprintf(f, "(G) CR3: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_CR3));
    fprintf(f, "(G) CR4: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_CR4));
    fprintf(f, "(G) Guest IA32 EFER: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_IA32_EFER));
    fprintf(f, "(G) RFLAGS: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_RFLAGS));
    fprintf(f, "(G) RIP: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_RIP));
    fprintf(f, "(G) RSP: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_RSP));
    fprintf(f, "(G) ES base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_ES_BASE));
    fprintf(f, "(G) CS base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_CS_BASE));
    fprintf(f, "(G) SS base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_SS_BASE));
    fprintf(f, "(G) DS base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_DS_BASE));
    fprintf(f, "(G) FS base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_FS_BASE));
    fprintf(f, "(G) GS base: 0x%llx\n",
            vmx->vmx_read(VMCS_GUEST_GS_BASE));
  }

private:
  Vmm::Vcpu_ptr get_vcpu() const
  { return static_cast<T const *>(this)->vcpu(); }
};

}
