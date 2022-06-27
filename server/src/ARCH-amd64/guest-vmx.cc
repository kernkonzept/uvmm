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

namespace Vmm {

template <>
int
Guest::handle_exit<Vmx_state>(Vmm::Vcpu_ptr vcpu, Vmx_state *vms)
{
  using Exit = Vmx_state::Exit;
  auto reason = vms->exit_reason();
  auto *regs = &vcpu->r;

  if (reason != Vmx_state::Exit::Exec_vmcall)
    trace().printf("Exit at guest IP 0x%lx SP 0x%lx with 0x%llx (Qual: 0x%llx)\n",
                   vms->ip(), vms->sp(),
                   vms->vmx_read(VMCS_EXIT_REASON),
                   vms->vmx_read(VMCS_EXIT_QUALIFICATION));

  switch (reason)
    {
    case Exit::Cpuid: return handle_cpuid(regs);

    case Exit::Exec_vmcall: return handle_vm_call(regs);

    case Exit::Io_access:
      {
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);
        unsigned qwidth = qual & 7;
        bool is_read = qual & 8;
        bool is_string = qual & 16;
        unsigned port = (qual >> 16) & 0xFFFFU;

        Dbg(Dbg::Dev, Dbg::Trace)
          .printf("VM exit: IO port access with exit qualification 0x%llx: "
                  "%s port 0x%x\n",
                  qual, is_read ? "read" : "write", port);

        if (is_string)
          {
            warn().printf("Unhandled string IO instruction @ 0x%lx: %s%s, port 0x%x! Skipped.\n",
                          vms->ip(), (qual & 0x20) ? "REP " : "",
                          is_read ? "INS" : "OUTS", port);
            // This is not entirely correct: SI/DI not incremented, REP prefix
            // not handled.
            return Jump_instr;
          }

        if (port == 0xcfb)
          Dbg(Dbg::Dev, Dbg::Trace)
            .printf(" 0xcfb access from ip: %lx\n", vms->ip());

        Mem_access::Width wd = Mem_access::Wd32;
        switch(qwidth)
          {
          // only 0,1,3 are valid values in the exit qualification.
          case 0: wd = Mem_access::Wd8; break;
          case 1: wd = Mem_access::Wd16; break;
          case 3: wd = Mem_access::Wd32; break;
          }

        return handle_io_access(port, is_read, wd, regs);
      }

    // Ept_violation needs to be checked here, as handle_mmio needs a vCPU ptr,
    // which cannot be passed to Vm_state/Vmx_state due to dependency reasons.
    case Exit::Ept_violation:
      {
        auto guest_phys_addr =
          vms->vmx_read(VMCS_GUEST_PHYSICAL_ADDRESS);
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);

        trace().printf("Exit reason due to EPT violation %i;  gp_addr 0x%llx, "
                       "qualification 0x%llx\n",
                       static_cast<unsigned>(reason), guest_phys_addr, qual);

        auto ret = handle_mmio(guest_phys_addr, vcpu);

        // EPT violation was handled check for IDT vectoring
        Vmx_state::Idt_vectoring_info vinfo = vms->idt_vectoring_info();
        if (vinfo.valid())
          vms->inject_event(vinfo);

        switch(ret)
          {
          case Retry: return L4_EOK;
          case Jump_instr: return Jump_instr;
          default: break;
          }

        warn().printf("Unhandled pagefault @ 0x%lx\n", vms->ip());
        warn().printf("Read: %llu, Write: %llu, Inst.: %llu Phys addr: 0x%llx\n",
                     qual & 1, qual & 2, qual & 4, guest_phys_addr);

        if (qual & 0x80)
          warn().printf("Linear address: 0x%llx\n",
                       vms->vmx_read(VMCS_GUEST_LINEAR_ADDRESS));
        return -L4_EINVAL;
      }

    // VMX specific exits
    case Exit::Exception_or_nmi:
      {
        Vmx_state::Idt_vectoring_info vinfo = vms->idt_vectoring_info();
        if (vinfo.valid())
          vms->inject_event(vinfo);
      }
      // FIXME entry info might be overwritten by exception handling
      // currently this isn't fully fletched anyways so this works for now.
      /* fall-through */
    case Exit::External_int:
      return vms->handle_exception_nmi_ext_int();

    case Exit::Interrupt_window:
    case Exit::Nmi_window:
      return L4_EOK;

    case Exit::Exec_halt:
      if (0)
        info().printf("vcpu%i:HALT @ 0x%llx! Activity state 0x%llx\n",
                      vcpu.get_vcpu_id(), vms->vmx_read(VMCS_GUEST_RIP),
                      vms->vmx_read(VMCS_GUEST_ACTIVITY_STATE));

      vms->halt();

      return Jump_instr;

    case Exit::Cr_access:
      return vms->handle_cr_access(regs);

    case Exit::Exec_rdmsr:
      if (!msr_devices_rwmsr(regs, false, vcpu.get_vcpu_id()))
        {
          warn().printf("Reading unsupported MSR 0x%lx\n", regs->cx);
          regs->ax = 0;
          regs->dx = 0;
          vms->inject_hw_exception(13, Vmx_state::Push_error_code, 0);
          return L4_EOK;
        }

      return Jump_instr;

    case Exit::Exec_wrmsr:
      if (msr_devices_rwmsr(regs, true, vcpu.get_vcpu_id()))
        return Jump_instr;
      else
        {
          warn().printf("Writing unsupported MSR 0x%lx\n", regs->cx);
          vms->inject_hw_exception(13, Vmx_state::Push_error_code, 0);
          return L4_EOK;
        }

    case Exit::Virtualized_eoi:
      Dbg().printf("INFO: EOI virtualized for vector 0x%llx\n",
                   vms->vmx_read(VMCS_EXIT_QUALIFICATION));
      // Trap like exit: IP already on next instruction
      return L4_EOK;

    case Exit::Exec_xsetbv:
      if (regs->cx == 0)
        {
          l4_uint64_t value = (l4_uint64_t(regs->ax) & 0xFFFFFFFF)
                              | (l4_uint64_t(regs->dx) << 32);
          vms->vmx_write(L4_VM_VMX_VMCS_XCR0, value);
          trace().printf("Setting xcr0 to 0x%llx\n", value);
          return Jump_instr;
        }
      Dbg().printf("Writing unknown extended control register %ld\n", regs->cx);
      return -L4_EINVAL;

    case Exit::Apic_write:
      // Trap like exit: IP already on next instruction
      assert(0); // Not supported
      return L4_EOK;

    case Exit::Task_switch:
    case Exit::Apic_access:
    case Exit::Ept_misconfig:
    case Exit::Page_mod_log_full:
    case Exit::Spp_related_event:
      // These cases need to check IDT-vectoring info for validity!

    default:
      {
        Dbg().printf("Exit at guest IP 0x%lx SP 0x%lx with 0x%llx (Qual: 0x%llx)\n",
                     vms->ip(), vms->sp(), vms->vmx_read(VMCS_EXIT_REASON),
                     vms->vmx_read(VMCS_EXIT_QUALIFICATION));

        unsigned reason_u = static_cast<unsigned>(reason);
        if (reason_u < sizeof(str_exit_reason) / sizeof(*str_exit_reason))
          Dbg().printf("Unhandled exit reason: %s (%d)\n",
                       str_exit_reason[reason_u], reason_u);
        else
          Dbg().printf("Unknown exit reason: 0x%x\n", reason_u);

        return -L4_ENOSYS;
      }
    }
}

} // namespace
