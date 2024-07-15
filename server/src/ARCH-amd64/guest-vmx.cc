/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 */

#include "guest.h"
#include "debug.h"
#include "vm_state_vmx.h"
#include "vmx_exit_to_str.h"
#include "event_recorder.h"

namespace Vmm {

template <>
int
Guest::handle_exit<Vmx_state>(Vmm::Cpu_dev *cpu, Vmx_state *vms)
{
  using Exit = Vmx_state::Exit;
  auto reason = vms->exit_reason();
  Vmm::Vcpu_ptr vcpu = cpu->vcpu();
  auto *regs = &vcpu->r;
  auto *ev_rec = recorder(vcpu.get_vcpu_id());
  unsigned vcpu_id = vcpu.get_vcpu_id();

  if (reason != Vmx_state::Exit::Exec_vmcall)
    trace().printf("[%3u]: Exit at guest IP 0x%lx SP 0x%lx with %llu ('%s') (Qual: 0x%llx)\n",
                   vcpu_id, vms->ip(), vms->sp(),
                   vms->vmx_read(VMCS_EXIT_REASON),
                   exit_reason_to_str(vms->vmx_read(VMCS_EXIT_REASON)),
                   vms->vmx_read(VMCS_EXIT_QUALIFICATION));

  switch (reason)
    {
    case Exit::Cpuid: return handle_cpuid(vcpu);

    case Exit::Exec_vmcall: return handle_vm_call(regs);

    case Exit::Io_access:
      {
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);
        unsigned qwidth = qual & 7;
        bool is_read = qual & 8;
        bool is_string = qual & 16;
        bool is_rep = qual & 32;
        bool is_imm = qual & 64;
        unsigned port = (qual >> 16) & 0xFFFFU;

        Dbg(Dbg::Dev, Dbg::Trace)
          .printf("[%3u]: VM exit @ 0x%lx: IO access with exit qualification "
                  "0x%llx: %s port 0x%x %s%s%s\n",
                  vcpu_id, vms->ip(), qual, is_read ? "read" : "write", port,
                  is_imm ? "immediate" : "in DX", is_string ? " string" : "",
                  is_rep ? " rep" : "");

        if (port == 0xcfb)
          Dbg(Dbg::Dev, Dbg::Trace)
            .printf("[%3u]: N.B.: 0xcfb IO port access @ 0x%lx\n", vcpu_id,
                    vms->ip());

        Mem_access::Width op_width;
        switch (qwidth)
          {
          // Only 0, 1, 3 are valid values in the exit qualification.
          case 0: op_width = Mem_access::Wd8; break;
          case 1: op_width = Mem_access::Wd16; break;
          case 3: op_width = Mem_access::Wd32; break;
          default:
            warn().printf("[%3u]: Invalid IO access size %u @ 0x%lx\n",
                          vcpu_id, qwidth, vms->ip());
            return Invalid_opcode;
          }

        if (!is_string)
          return handle_io_access(port, is_read, op_width, regs);

        warn().printf("[%3u]: Unhandled string IO instruction @ 0x%lx: "
                      "%s%s, port 0x%x! Skipped.\n",
                      vcpu_id, vms->ip(), is_rep ? "REP " : "",
                      is_read ? "INS" : "OUTS", port);
        // This is not entirely correct: SI/DI not incremented, REP prefix
        // not handled.
        return Jump_instr;
      }

    // Ept_violation needs to be checked here, as handle_mmio needs a vCPU ptr,
    // which cannot be passed to Vm_state/Vmx_state due to dependency reasons.
    case Exit::Ept_violation:
      {
        auto guest_phys_addr =
          vms->vmx_read(VMCS_GUEST_PHYSICAL_ADDRESS);
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);

        trace().printf("[%3u]: Exit reason due to EPT violation %i;  gp_addr "
                       "0x%llx, qualification 0x%llx\n",
                       vcpu_id, static_cast<unsigned>(reason), guest_phys_addr,
                       qual);

        auto ret = handle_mmio(guest_phys_addr, vcpu);

        // XXX Idt_vectoring_info could be valid.

        switch(ret)
          {
          case Retry: return L4_EOK;
          case Jump_instr: return Jump_instr;
          default: break;
          }

        warn().printf("[%3u]: Unhandled pagefault @ 0x%lx\n", vcpu_id,
                      vms->ip());
        warn().printf("[%3u]: Read: %llu, Write: %llu, Inst.: %llu Phys addr: "
                      "0x%llx\n",
                      vcpu_id, qual & 1, qual & 2, qual & 4, guest_phys_addr);

        if (qual & 0x80)
          warn().printf("[%3u]: Linear address: 0x%llx\n", vcpu_id,
                        vms->vmx_read(VMCS_GUEST_LINEAR_ADDRESS));
        return -L4_EINVAL;
      }

    // VMX specific exits
    case Exit::Exception_or_nmi:
      {
        // XXX Idt_vectoring_info could be valid.
      }
      // FIXME entry info might be overwritten by exception handling
      // currently this isn't fully fletched anyways so this works for now.
      /* fall-through */
    case Exit::External_int:
      return vms->handle_exception_nmi_ext_int(ev_rec);

    case Exit::Interrupt_window:
    case Exit::Nmi_window:
      return Retry;

    case Exit::Exec_halt:
      if (0)
        info().printf("[%3u]: HALT @ 0x%llx! Activity state 0x%llx\n",
                      vcpu_id, vms->vmx_read(VMCS_GUEST_RIP),
                      vms->vmx_read(VMCS_GUEST_ACTIVITY_STATE));

      vms->halt();
      cpu->halt_cpu();
      return Jump_instr;

    case Exit::Exec_rdpmc:
      return General_protection;

    case Exit::Cr_access:
      return vms->handle_cr_access(regs);

    case Exit::Exec_rdmsr:
      if (!msr_devices_rwmsr(regs, false, vcpu_id))
        {
          warn().printf("[%3u]: Reading unsupported MSR 0x%lx\n", vcpu_id,
                        regs->cx);
          regs->ax = 0;
          regs->dx = 0;
          return General_protection;
        }

      return Jump_instr;

    case Exit::Exec_wrmsr:
      {
        bool has_already_exception = ev_rec->has_exception();
        if (!msr_devices_rwmsr(regs, true, vcpu.get_vcpu_id()))
          {
            warn().printf("[%3u]: Writing unsupported MSR 0x%lx\n", vcpu_id,
                          regs->cx);
            return General_protection;
          }

        // Writing an MSR e.g. IA32_EFER can lead to injection of a HW exception.
        // In this case the instruction wasn't emulated, thus don't jump it.
        if (!has_already_exception && ev_rec->has_exception())
          return Retry;
        else
          return Jump_instr;
      }
    case Exit::Virtualized_eoi:
      Dbg().printf("[%3u]: INFO: EOI virtualized for vector 0x%llx\n",
                   vcpu_id, vms->vmx_read(VMCS_EXIT_QUALIFICATION));
      // Trap like exit: IP already on next instruction
      return L4_EOK;

    case Exit::Exec_xsetbv:
      if (regs->cx == 0)
        {
          l4_uint64_t value = (l4_uint64_t(regs->ax) & 0xFFFFFFFF)
                              | (l4_uint64_t(regs->dx) << 32);
          vms->vmx_write(L4_VM_VMX_VMCS_XCR0, value);
          trace().printf("[%3u]: Setting xcr0 to 0x%llx\n", vcpu_id, value);
          return Jump_instr;
        }
      Dbg().printf("[%3u]: Writing unknown extended control register %ld\n",
                   vcpu_id, regs->cx);
      return -L4_EINVAL;

    case Exit::Apic_write:
      // Trap like exit: IP already on next instruction
      assert(0); // Not supported
      return L4_EOK;

    case Exit::Mov_debug_reg:
      {
        l4_uint64_t qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);
        unsigned char dbg_reg = qual & 0x7;
        bool read = qual & (1 << 4);
        unsigned char gp_reg = (qual >> 8) & 0xf;
        // check CR4.DE
        if (dbg_reg == 4 || dbg_reg == 5)
          {
            if (vms->vmx_read(VMCS_GUEST_CR4) & (1U << 3)) // CR4.DE set?
              return Invalid_opcode;
            // else: alias to DR6 & DR7
          }

        if (read)
          {
            if (gp_reg == 0x4)
              regs->sp = 0UL;
            else
              {
                l4_umword_t *r = &(regs->ax);
                *(r - gp_reg) = 0UL;
              }
          }
        // else: ignore writes
        trace().printf("[%3u]: MOV DR exit: %s DR%u %s GP%u. Value: 0x%lx\n",
                       vcpu_id, read ? "read" : "write", dbg_reg,
                       read ? "to" : "from", gp_reg, *(&(regs->ax) - gp_reg));
        return Jump_instr;
      }

    case Exit::Exec_vmclear:
    case Exit::Exec_vmlaunch:
    case Exit::Exec_vmptrld:
    case Exit::Exec_vmptrst:
    case Exit::Exec_vmread:
    case Exit::Exec_vmresume:
    case Exit::Exec_vmwrite:
    case Exit::Exec_vmxoff:
    case Exit::Exec_vmxon:
    case Exit::Exec_invept:
    case Exit::Exec_invvpid:
    case Exit::Exec_rdtscp:
      // Unsupported instructions, inject undefined opcode exception
      return Invalid_opcode;

    case Exit::Triple_fault:
      // Double-fault experienced exception. Set core into shutdown mode.
      info().printf("[%3u]: Triple fault exit at IP 0x%lx. Core is in shutdown "
                    "mode.\n",
                    vcpu_id, vms->ip());
      vcpu.dump_regs_t(vms->ip(), info());

      // move CPU into stop state
      cpu->stop();
      return Retry;

    case Exit::Entry_fail_invalid_guest:
      {
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);
        auto reason_raw = vms->vmx_read(VMCS_EXIT_REASON);
        auto ip = vms->ip();
        auto insn_err = vms->vmx_read(VMCS_VM_INSN_ERROR);
        auto entry_exc_err = vms->vmx_read(VMCS_VM_ENTRY_EXCEPTION_ERROR);

        Dbg().printf("VM-entry failure due to invalid guest state:\n"
                     "Exit reason raw: 0x%llx\n"
                     "Exit qualification: 0x%llx\n"
                     "IP: 0x%lx\n"
                     "Instruction error: 0x%llx\n"
                     "Entry exception error: 0x%llx\n",
                     reason_raw, qual, ip, insn_err, entry_exc_err
                     );
      }
      /* fall-through */

    case Exit::Task_switch:
    case Exit::Apic_access:
    case Exit::Ept_misconfig:
    case Exit::Page_mod_log_full:
    case Exit::Spp_related_event:
      // These cases need to check IDT-vectoring info for validity!

    default:
      {
        Dbg().printf("[%3u]: Exit at guest IP 0x%lx SP 0x%lx with 0x%llx "
                     "(Qual: 0x%llx)\n",
                     vcpu_id, vms->ip(), vms->sp(),
                     vms->vmx_read(VMCS_EXIT_REASON),
                     vms->vmx_read(VMCS_EXIT_QUALIFICATION));

        unsigned reason_u = static_cast<unsigned>(reason);
        if (reason_u < sizeof(str_exit_reason) / sizeof(*str_exit_reason))
          Dbg().printf("[%3u]: Unhandled exit reason: %s (%d)\n",
                       vcpu_id, str_exit_reason[reason_u], reason_u);
        else
          Dbg().printf("[%3u]: Unknown exit reason: 0x%x\n", vcpu_id, reason_u);

        return -L4_ENOSYS;
      }
    }
}

} // namespace
