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
Guest::handle_exit<Svm_state>(Vmm::Cpu_dev *cpu, Svm_state *vms)
{
  Vmm::Vcpu_ptr vcpu = cpu->vcpu();
  l4_vcpu_regs_t *regs = &vcpu->r;
  unsigned vcpu_id = vcpu.get_vcpu_id();

  // Synchronize VMCB.StateSaveArea.RAX with Vcpu_regs.RAX. This is necessary
  // because the code shared between VMX and SVM uses the RAX in Vcpu_regs,
  // since in VMX only RSP and RIP are stored in the "guest state save area".
  Rax_guard rax_guard(vms, regs);

  // Initially all fields are clean
  vms->mark_all_clean();

  auto *ev_rec = recorder(vcpu.get_vcpu_id());
  using Exit = Svm_state::Exit;
  Exit reason = vms->exit_code();

  switch (reason)
    {
    // TODO: Lacks handlers for some of the enabled intercepts, which have not
    // been triggered during development. If one of these interceptions is hit,
    // first an error message is printed and then the VM is stopped.
    case Exit::Cpuid: return handle_cpuid(vcpu);

    case Exit::Vmmcall: return handle_vm_call(regs);

    case Exit::Ioio:
      {
        Svm_state::Io_info info(vms->exit_info1());
        bool is_read = info.type() == 1;
        unsigned port = info.port();

        trace().printf("[%3u]: VM exit: IO port access with exit info 0x%x: "
                       "%s port 0x%x\n",
                       vcpu_id, info.raw, is_read ? "read" : "write", port);

        if (info.str())
        {
          warn().printf("[%3u]: String based port access is not supported!\n",
                        vcpu_id);
          return Jump_instr;
        }

        // rep prefix is only specified for string port access instructions,
        // which are not yet supported anyway.
        if (info.rep())
        {
          warn().printf("[%3u]: Repeated port access is not supported!\n",
                        vcpu_id);
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
          "[%3u]: Nested page fault at gp_addr 0x%lx with exit info 0x%llx\n",
          vcpu_id, guest_phys_addr, info.raw);

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
                  warn().printf("[%3u]: Could not determine opcode for MMIO "
                                "access\n",
                                vcpu_id);
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
                  warn().printf("[%3u]: Could not determine next ip for MMIO "
                                "access\n",
                                vcpu_id);
                  return -L4_EINVAL;
                }
            }
          default: break;
          }

        warn().printf("[%3u]: Unhandled nested page fault @ 0x%lx\n", vcpu_id,
                      vms->ip());
        warn()
          .printf("[%3u]: Present: %u, Type: %s, Inst.: %u Phys addr: 0x%lx\n",
                  vcpu_id, info.present().get(),
                  info.write() ? "Write" : "Read", info.inst().get(),
                  guest_phys_addr);
        return -L4_EINVAL;
      }

    case Exit::Msr:
      {
        bool write = vms->exit_info1() == 1;
        bool has_already_exception = ev_rec->has_exception();
        if (!msr_devices_rwmsr(regs, write, vcpu.get_vcpu_id()))
          {
            info().printf("[%3u]: %s unsupported MSR 0x%lx\n", vcpu_id,
                          write ? "Writing" : "Reading", regs->cx);
            ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
            return Retry;
          }

        if (!has_already_exception && ev_rec->has_exception())
          return Retry;
        else
          return Jump_instr;
      }

    case Exit::Hlt:
      trace().printf("[%3u]: HALT 0x%lx!\n", vcpu_id, vms->ip());
      vms->halt();
      cpu->halt_cpu();
      return Jump_instr;

    case Exit::Cr0_sel_write:
      return vms->handle_cr0_write(regs);

    case Exit::Xsetbv:
      return vms->handle_xsetbv(regs);

    case Exit::Vintr:
      // Used as interrupt window notification, handled in run_vm().
      return L4_EOK;

    case Exit::Rdpmc:
      ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
      return Retry;

    case Exit::Dr0_read:
    case Exit::Dr1_read:
    case Exit::Dr2_read:
    case Exit::Dr3_read:
    case Exit::Dr4_read:
    case Exit::Dr5_read:
    case Exit::Dr6_read:
    case Exit::Dr7_read:
      {
        int i = static_cast<int>(reason) - static_cast<int>(Exit::Dr0_read);
        if (i == 4 || i == 5)
          {
            if (vms->vmcb()->state_save_area.cr4 & (1U << 3)) // CR4.DE set?
              {
                ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
                return Retry;
              }
            // else: alias to DR6 & DR7
          }

        unsigned char gp_reg = vms->vmcb()->control_area.exitinfo1 & 0xf;
        *(&(regs->ax) - gp_reg) = 0;
        return Jump_instr;
      }
    case Exit::Dr8_read:
    case Exit::Dr9_read:
    case Exit::Dr10_read:
    case Exit::Dr11_read:
    case Exit::Dr12_read:
    case Exit::Dr13_read:
    case Exit::Dr14_read:
    case Exit::Dr15_read:
      // AMD APM Vol 2 Chapter 13.1.1.5 "64-Bit-Mode Extended Debug Registers":
      // DR8-15 are not implemented -> #UD
      ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
      return Retry;

    case Exit::Dr0_write:
    case Exit::Dr1_write:
    case Exit::Dr2_write:
    case Exit::Dr3_write:
    case Exit::Dr4_write:
    case Exit::Dr5_write:
    case Exit::Dr6_write:
    case Exit::Dr7_write:
      {
        // Ignore the writes, except to illegal registers.
        int i = static_cast<int>(reason) - static_cast<int>(Exit::Dr0_read);
        if (i == 4 || i == 5)
          {
            if (vms->vmcb()->state_save_area.cr4 & (1U << 3)) // CR4.DE set?
              {
                ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
                return Retry;
              }
          }
        return Jump_instr;
      }
    case Exit::Dr8_write:
    case Exit::Dr9_write:
    case Exit::Dr10_write:
    case Exit::Dr11_write:
    case Exit::Dr12_write:
    case Exit::Dr13_write:
    case Exit::Dr14_write:
    case Exit::Dr15_write:
      // AMD APM Vol 2 Chapter 13.1.1.5 "64-Bit-Mode Extended Debug Registers":
      // DR8-15 are not implemented -> #UD
      ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
      return Retry;

    case Exit::Vmrun:
    case Exit::Vmload:
    case Exit::Vmsave:
    case Exit::Stgi:
    case Exit::Clgi:
    case Exit::Skinit:
    case Exit::Rdtscp:
      // Unsupported instructions, inject undefined opcode exception
      ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
      return Retry;

    case Exit::Sw_int:
      {
        // exit_info1[7:0] contains vector
        l4_uint32_t sw_int_num = vms->exit_info1() & 0xff;

        using Event_sw_int = Event_sw_generic<4>;
        ev_rec->make_add_event<Event_sw_int>(Event_prio::Sw_intN, sw_int_num,
                                             0U);

        return Retry;
      }

    case Exit::Icebp:
      // Emulating ICEBP this way leads to an additional DPL check, which INT1
      // does not do normally, but normally, the INT1 is for HW vendors only.
      ev_rec->make_add_event<Event_exc>(Event_prio::Sw_int1, 1); // #DB

      return Retry;

    case Exit::Shutdown:
      // Any event that triggeres a shutdown, e.g. triple fault, lands here.
      info().printf("[%3u]: Shutdown intercept triggered at IP 0x%lx. Core in "
                   "shutdown mode.\n",
                   vcpu_id, vms->ip());
      vcpu.dump_regs_t(vms->ip(), info());

      // move CPU into stop state
      cpu->stop();

      return Retry;

    default:
      if (reason >= Exit::Excp_0 && reason <= Exit::Excp_31)
      {
        int exc_num = static_cast<unsigned>(reason)
                      - static_cast<unsigned>(Exit::Excp_0);
        return vms->handle_hardware_exception(ev_rec, exc_num);
      }

      warn().printf("[%3u]: Exit at guest IP 0x%lx with 0x%x (Info1: 0x%llx, "
                    "Info2: 0x%llx)\n",
                    vcpu_id, vms->ip(), static_cast<unsigned>(reason),
                    vms->exit_info1(), vms->exit_info2());

      auto str_exit_code = vms->str_exit_code(reason);
      if (str_exit_code)
        warn().printf("[%3u]: Unhandled exit reason: %s (%d)\n",
                      vcpu_id, str_exit_code, static_cast<unsigned>(reason));
      else
        warn().printf("[%3u]: Unknown exit reason: 0x%x\n",
                      vcpu_id, static_cast<unsigned>(reason));

      return -L4_ENOSYS;
    }
}

} // namespace
