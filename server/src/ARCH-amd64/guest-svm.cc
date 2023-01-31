/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 *            Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include "guest.h"
#include "debug.h"
#include "vm_state_svm.h"

namespace Vmm {

/**
 * Synchronize VMCB.StateSaveArea.RAX with Vcpu_regs.RAX.
 */
class Rax_guard
{
public:
  Rax_guard(Svm_state *vms, l4_vcpu_regs_t *regs) : _vms(vms), _regs(regs)
  { _regs->ax = _vms->vmcb()->state_save_area.rax; }

  ~Rax_guard()
  { _vms->vmcb()->state_save_area.rax = _regs->ax; }

private:
  Svm_state *_vms;
  l4_vcpu_regs_t *_regs;
};

template <>
int
Guest::handle_exit<Svm_state>(Vmm::Vcpu_ptr vcpu, Svm_state *vms)
{
  l4_vcpu_regs_t *regs = &vcpu->r;

  // Synchronize VMCB.StateSaveArea.RAX with Vcpu_regs.RAX. This is necessary
  // because the code shared between VMX and SVM uses the RAX in Vcpu_regs,
  // since in VMX only RSP and RIP are stored in the "guest state save area".
  Rax_guard rax_guard(vms, regs);

  // Initially all fields are clean
  vms->mark_all_clean();

  using Exit = Svm_state::Exit;
  Exit reason = vms->exit_code();

  switch (reason)
    {
    // TODO: Lacks handlers for some of the enabled intercepts, which have not
    // been triggered during development. If one of these interceptions is hit,
    // first an error message is printed and then the VM is stopped.
    case Exit::Cpuid: return handle_cpuid(regs);

    case Exit::Vmmcall: return handle_vm_call(regs);

    case Exit::Ioio:
      {
        Svm_state::Io_info info(vms->exit_info1());
        bool is_read = info.type() == 1;
        unsigned port = info.port();

        trace().printf(
          "VM exit: IO port access with exit info 0x%x: %s port 0x%x\n",
          info.raw, is_read ? "read" : "write", port);

        if (info.str())
        {
          warn().printf("String based port access is not supported!\n");
          return Jump_instr;
        }

        // rep prefix is only specified for string port access instructions,
        // which are not yet supported anyway.
        if (info.rep())
        {
          warn().printf("Repeated port access is not supported!\n");
          return Jump_instr;
        }

        Mem_access::Width wd = Mem_access::Wd32;
        switch (info.data_size())
          {
          case 1: wd = Mem_access::Wd8; break;
          case 2: wd = Mem_access::Wd16; break;
          case 4: wd = Mem_access::Wd32; break;
          }

        return handle_io_access(port, is_read, wd, regs);
      }

    case Exit::Nested_page_fault:
      {
        l4_addr_t guest_phys_addr = vms->exit_info2();
        Svm_state::Npf_info info(vms->exit_info1());

        trace().printf(
          "Nested page fault at gp_addr 0x%lx with exit info 0x%llx\n",
          guest_phys_addr, info.raw);

        // TODO: Use instruction bytes provided by decode assist
        switch(handle_mmio(guest_phys_addr, vcpu))
          {
          case Retry: return L4_EOK;
          case Jump_instr:
            {
              // TODO: Avoid fetching and decoding the current instruction again
              // (handle_mmio already did that once).
              l4_uint64_t opcode;
              try
                {
                  // overwrite the virtual IP with the physical OP code
                  opcode = vcpu.get_pt_walker()->walk(vms->cr3(), vms->ip());
                }
              catch (L4::Runtime_error &e)
                {
                  warn().printf("Could not determine opcode for MMIO access\n");
                  return -L4_EINVAL;
                }

              // TODO: Check inst_buf points to valid memory and figure out its size.
              unsigned char *inst_buf = reinterpret_cast<unsigned char *>(opcode);
              unsigned inst_buf_len = 15;

              // The next sequential instruction pointer (nRIP) is not saved for
              // nested page faults:
              // > nRIP is saved for instruction intercepts as well as MSR and
              // > IOIO intercepts and exceptions caused by the INT3, INTO,
              // > and BOUND instructions.
              // > For all other intercepts, nRIP is reset to zero.
              if (vms->determine_next_ip_from_ip(regs, inst_buf, inst_buf_len))
                return Jump_instr;
              else
                {
                  warn().printf("Could not determine next ip for MMIO access\n");
                  return -L4_EINVAL;
                }
            }
          default: break;
          }

        warn().printf("Unhandled nested page fault @ 0x%lx\n", vms->ip());
        warn().printf("Present: %u, Type: %s, Inst.: %u Phys addr: 0x%lx\n",
                      info.present().get(), info.write() ? "Write" : "Read",
                      info.inst().get(), guest_phys_addr);
        return -L4_EINVAL;
      }

    case Exit::Msr:
      {
        bool write = vms->exit_info1() == 1;
        if (msr_devices_rwmsr(regs, write, vcpu.get_vcpu_id()))
          return Jump_instr;
        else
          {
            info().printf("%s unsupported MSR 0x%lx\n",
                          write ? "Writing" : "Reading", regs->cx);
            vms->inject_hw_exception(13, Svm_state::Push_error_code, 0);
            return L4_EOK;
          }
      }

    case Exit::Hlt:
      trace().printf("HALT 0x%lx!\n", vms->ip());
      vms->halt();
      return Jump_instr;

    case Exit::Cr0_sel_write:
      return vms->handle_cr0_write(regs);

    case Exit::Xsetbv:
      return vms->handle_xsetbv(regs);

    case Exit::Vintr:
      // Used as interrupt window notification, handled in run_vm().
      return L4_EOK;

    default:
      if (reason >= Exit::Excp_0 && reason <= Exit::Excp_31)
      {
        int exc_num = static_cast<unsigned>(reason)
                      - static_cast<unsigned>(Exit::Excp_0);
        return vms->handle_hardware_exception(exc_num);
      }

      warn().printf("Exit at guest IP 0x%lx with 0x%x (Info1: 0x%llx, Info2: 0x%llx)\n",
                    vms->ip(), static_cast<unsigned>(reason),
                    vms->exit_info1(), vms->exit_info2());

      auto str_exit_code = vms->str_exit_code(reason);
      if (str_exit_code)
        warn().printf("Unhandled exit reason: %s (%d)\n",
                      str_exit_code, static_cast<unsigned>(reason));
      else
        warn().printf("Unknown exit reason: 0x%x\n",
                      static_cast<unsigned>(reason));

      return -L4_ENOSYS;
    }
}

} // namespace
