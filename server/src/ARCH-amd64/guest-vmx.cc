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
Guest::handle_exit<Vmx_state>(Vmm::Vcpu_ptr vcpu, Vmx_state *vms)
{
  using Exit = Vmx_state::Exit;
  auto reason = vms->exit_reason();
  auto *regs = &vcpu->r;
  auto *ev_rec = recorder(vcpu.get_vcpu_id());

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

        // XXX Idt_vectoring_info could be valid.

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
        info().printf("vcpu%i:HALT @ 0x%llx! Activity state 0x%llx\n",
                      vcpu.get_vcpu_id(), vms->vmx_read(VMCS_GUEST_RIP),
                      vms->vmx_read(VMCS_GUEST_ACTIVITY_STATE));

      vms->halt();

      return Jump_instr;

    case Exit::Cr_access:
      return vms->handle_cr_access(regs, ev_rec);

    case Exit::Exec_rdmsr:
      if (!msr_devices_rwmsr(regs, false, vcpu.get_vcpu_id()))
        {
          warn().printf("Reading unsupported MSR 0x%lx\n", regs->cx);
          regs->ax = 0;
          regs->dx = 0;
          ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
          return Retry;
        }

      return Jump_instr;

    case Exit::Exec_wrmsr:
      {
        bool has_already_exception = ev_rec->has_exception();
        if (!msr_devices_rwmsr(regs, true, vcpu.get_vcpu_id()))
          {
            warn().printf("Writing unsupported MSR 0x%lx\n", regs->cx);
            ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
            return Retry;
          }
        // Writing an MSR e.g. IA32_EFER can lead to injection of a HW exception.
        // In this case the instruction wasn't emulated, thus don't jump it.
        if (!has_already_exception && ev_rec->has_exception())
          return Retry;
        else
          return Jump_instr;
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
              {
                ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
                return Retry;
              }
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
        trace().printf("MOV DR exit: %s DR%u %s GP%u. Value: 0x%lx\n",
                       read ? "read" : "write", dbg_reg, read ? "to" : "from",
                       gp_reg, *(&(regs->ax) - gp_reg));
        return Jump_instr;
      }

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
