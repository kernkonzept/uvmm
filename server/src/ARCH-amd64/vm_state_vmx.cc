/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2018, 2020-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */

#include <l4/re/env>
#include "vm_state_vmx.h"
#include "consts.h"
#include "event_recorder.h"

namespace Vmm {

Vm_state::~Vm_state() = default;

enum : unsigned long
{
  Misc_enable_fast_string = 1UL,

  Cr0_pe_bit = 1UL,
  Cr0_pg_bit = 1UL << 31,

  Cr4_pae_bit = 1UL << 5,
  Cr4_la57_bit = 1UL << 12,

  Efer_syscall_enable_bit = 1UL,
  Efer_lme_bit = 1UL << 8,
  Efer_lma_bit = 1UL << 10,
  Efer_nxe_bit = 1UL << 11,
  // EFER.LMA writes are ignored. Other bits reserved.
  Efer_write_mask = Efer_syscall_enable_bit | Efer_lme_bit | Efer_nxe_bit,

  Entry_ctrl_ia32e_bit = 1UL << 9,
};

Vmx_state::Vmx_state(void *vmcs)
  :  _vmcs(vmcs),
    _hw_vmcs(L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Vcpu_context>(),
                          "Failed to allocate hardware VMCS capability."))
{
  // Create the hardware VMCS
  auto *env = L4Re::Env::env();
  auto ret = env->factory()->create(_hw_vmcs.get(), L4_PROTO_VCPU_CONTEXT);
  if (l4_error(ret) < 0)
    L4Re::chksys(ret, "Cannot create guest VM hardware VMCS. Virtualization "
                      "support may be missing.");

  if (l4_vm_vmx_get_caps(vmcs, L4_VM_VMX_NESTED_REVISION) != 0)
    info().printf("vCPU interface supports nested virtualization. However, "
                  "uvmm does not implement nested virtualization.\n");
}

/**
 * Handle exits due to HW/SW exceptions, NMIs, and external interrupts.
 *
 * Bit 11, error_valid, is not set if, an external interrupt occurred and
 * 'acknowledge interrupt on exit' is not set in the exit controls.
 */
int
Vmx_state::handle_exception_nmi_ext_int(Event_recorder *ev_rec)
{
  Vm_exit_int_info interrupt_info = exit_int_info();

  l4_uint32_t interrupt_error = 0;
  if (interrupt_info.error_valid())
    interrupt_error =
      (l4_uint32_t)vmx_read(VMCS_VM_EXIT_INTERRUPT_ERROR);

  trace().printf("Exception, NMI or external interrupt exit: 0x%x/0x%x\n",
                 interrupt_info.field, (unsigned)interrupt_error);

  switch ((interrupt_info.type()))
    {
    // Pin-based controlls not set, Ext_int and NMI should not happen.
    case 0x0: warn().printf("External interrupt\n"); break;
    case 0x2: warn().printf("NMI\n"); break;

    case 0x3:
      return handle_hardware_exception(ev_rec, interrupt_info.vector(),
                                       interrupt_error);

    case 0x4: // software interrupt: INT n
      // Software interrupt event record
      using Event_sw_int = Event_sw_generic<4>;

      ev_rec->make_add_event<Event_sw_int>(Event_prio::Sw_intN,
                                           interrupt_info.vector(),
                                           2U); // opcode + operand
      return Retry;

    case 0x5: // priviledged software exception: INT1
      // Priveledged software exception event record
      using Event_priv_sw_exc = Event_sw_generic<5>;

      ev_rec->make_add_event<Event_priv_sw_exc>(Event_prio::Sw_int1, 1, 1U);
      return Retry;

    case 0x6: // software exception: INT3, INTO
      {
        // Software exception event record
        using Event_sw_exc = Event_sw_generic<6>;

        unsigned vec = interrupt_info.vector();
        if (vec == 3)
          {
            ev_rec->make_add_event<Event_sw_exc>(Event_prio::Sw_int3, vec, 1U);
            return Retry;
          }
        else if (vec == 4)
          {
            ev_rec->make_add_event<Event_sw_exc>(Event_prio::Sw_intO, vec, 1U);
            return Retry;
          }
        else
          // not defined in Intel SDM; leave this here as debug hint.
          warn().printf("Unknown software exception %u\n", vec);

      break;
        }
    default:
      warn().printf("Unknown interrupt type: %u, vector: %u\n",
                    interrupt_info.type().get(), interrupt_info.vector().get());
      break;
    }

  return -L4_ENOSYS;
}

bool
Vmx_state::read_msr(unsigned msr, l4_uint64_t *value) const
{
  unsigned shadow = msr_shadow_reg(msr);
  if (shadow > 0)
    {
      *value = vmx_read(shadow);
    }
  else
    {
      switch (msr)
        {
        case 0x17: // IA32_PLATFORM_ID
          *value = 0U;
          break;
        case 0x1a0: // IA32_MISC_ENABLE
          *value = Misc_enable_fast_string;
          break;
        case 0x3a: // IA32_FEATURE_CONTROL
          // Lock register so the guest does not try to enable anything.
          *value = 1U;
          break;
        case 0x277: // IA32_PAT
          *value = vmx_read(VMCS_GUEST_IA32_PAT);
          break;
        case 0xc0000080: // efer
          *value = vmx_read(VMCS_GUEST_IA32_EFER);
          break;

        /*
         * Non-architectural MSRs known to be probed by Linux that can be
         * safely ignored:
         *   0xce // MSR_PLATFORM_INFO
         *   0x33 // TEST_CTRL
         *   0x34 // MSR_SMI_COUNT
         *  0x140 // MISC_FEATURE_ENABLES
         *  0x64e // MSR_PPERF
         *  0x639 // MSR_PP0_ENERGY_STATUS
         *  0x611 // MSR_PKG_ENERGY_STATUS
         *  0x619 // MSR_DRAM_ENERGY_STATUS
         *  0x641 // MSR_PP1_ENERGY_STATUS
         *  0x64d // MSR_PLATFORM_ENERGY_COUNTER
         *  0x606 // MSR_RAPL_POWER_UNIT
         */
        default:
          return false;
        }
    }

  return true;
}

bool
Vmx_state::write_msr(unsigned msr, l4_uint64_t value, Event_recorder *ev_rec)
{
  unsigned shadow = msr_shadow_reg(msr);
  if (shadow > 0)
    {
      vmx_write(shadow, value);
      return true;
    }

  switch (msr)
    {
    case 0x277: // IA32_PAT
      // sanitization of 7 PAT values
      // 0xF8 are reserved bits
      // 0x2 and 0x3 are reserved encodings
      // usage of reserved bits and encodings results in a #GP
      if (value & 0xF8F8F8F8F8F8F8F8ULL)
        {
          ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
          break;
        }

      for (unsigned i = 0; i < 7; ++i)
        {
          l4_uint64_t const PAi_mask = (value & (0x7ULL << i * 8)) >> i * 8;
          if ((PAi_mask == 0x2ULL) || (PAi_mask == 0x3ULL))
            {
              ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
              break;
            }
        }

      vmx_write(VMCS_GUEST_IA32_PAT, value);
      break;
    case 0xc0000080: // efer
      {
        l4_uint64_t old_efer = vmx_read(VMCS_GUEST_IA32_EFER);
        // LMA writes are ignored.
        l4_uint64_t efer = (value & Efer_write_mask) | (old_efer & Efer_lma_bit);
        l4_uint64_t cr0 = vmx_read(VMCS_GUEST_CR0);

        trace().printf("IA32_EFER write: CR0: 0x%llx, old efer 0x%llx, "
                      "new efer 0x%llx\n",
                      cr0, old_efer, efer);

        if (cr0 & Cr0_pg_bit)
          {
            // Can't change LME while CR0.PG is set. SDM vol 3. 4.1
            if ((efer & Efer_lme_bit) != (old_efer & Efer_lme_bit))
              {
                // Inject GPF and do not write IA32_EFER
                ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
                break;
              }
          }

        vmx_write(VMCS_GUEST_IA32_EFER, efer);
        break;
      }
    case 0x8b: // IA32_BIOS_SIGN_ID
    case 0x140:  // unknown in Intel 6th gen, but MISC_FEATURE register for xeon
      break;
    case 0x1a0:
      warn().printf("Writing MSR 0x%x IA32_MISC_ENABLED 0x%llx\n", msr, value);
      break;
    case 0xe01: // MSR_UNC_PERF_GLOBAL_CTRL
      // can all be savely ignored
      break;

    default:
      return false;
    }

  return true;
}

int
Vmx_state::handle_cr_access(l4_vcpu_regs_t *regs)
{
  auto qual = vmx_read(VMCS_EXIT_QUALIFICATION);
  int crnum;
  l4_umword_t newval;

  switch ((qual >> 4) & 3)
    {
    case 0: // mov to cr
      crnum = qual & 0xF;
      switch ((qual >> 8) & 0xF)
        {
        case 0: newval = regs->ax; break;
        case 1: newval = regs->cx; break;
        case 2: newval = regs->dx; break;
        case 3: newval = regs->bx; break;
        case 4: newval = vmx_read(VMCS_GUEST_RSP); break;
        case 5: newval = regs->bp; break;
        case 6: newval = regs->si; break;
        case 7: newval = regs->di; break;
        case 8: newval = regs->r8; break;
        case 9: newval = regs->r9; break;
        case 10: newval = regs->r10; break;
        case 11: newval = regs->r11; break;
        case 12: newval = regs->r12; break;
        case 13: newval = regs->r13; break;
        case 14: newval = regs->r14; break;
        case 15: newval = regs->r15; break;
        default:
          warn().printf("Loading CR from unknown register\n");
          return -L4_EINVAL;
        }
      break;
    case 2: // clts
      crnum = 0;
      newval = vmx_read(VMCS_GUEST_CR0) & ~(1ULL << 3);
      break;
    default:
      warn().printf("Unknown CR action %lld.\n", (qual >> 4) & 3);
      return -L4_EINVAL;
    }

  switch (crnum)
    {
    case 0:
      {
        auto old_cr0 = vmx_read(VMCS_GUEST_CR0);
        trace().printf("Write to cr0: 0x%llx -> 0x%lx\n", old_cr0, newval);

        l4_uint64_t cr4 = vmx_read(VMCS_GUEST_CR4);
        l4_uint64_t efer = vmx_read(VMCS_GUEST_IA32_EFER);

        // enable paging
        if ((newval & Cr0_pg_bit) && !(old_cr0 & Cr0_pg_bit))
          {
            if (   (!(cr4 & Cr4_pae_bit) && (efer & Efer_lme_bit))
                || (!(efer & Efer_lme_bit) && (cr4 & Cr4_la57_bit)))
              {
                // inject GPF and do not write CR0
                return General_protection;
              }

            // LA57:   Cr4.PAE,  EFER.LME,  Cr4.LA57
            // IA32e:  Cr4.PAE,  EFER.LME, !Cr4.LA57
            // PAE:    Cr4.PAE, !EFER.LME, !Cr4.LA57
            // 32bit: !Cr4.PAE, !EFER.LME, !Cr4.LA57
            if ((cr4 & Cr4_pae_bit) && (efer & Efer_lme_bit))
              {
                if (cr4 & Cr4_la57_bit)
                  info().printf("Enable LA57 paging\n");
                else
                  info().printf("Enable IA32e paging\n");

                vmx_write(VMCS_VM_ENTRY_CTLS,
                          vmx_read(VMCS_VM_ENTRY_CTLS) | Entry_ctrl_ia32e_bit);
                // Contrary to SDM Vol 3, 24.8.1. IA32_EFER.LMA is not set to
                // the value of ENTRY_CTLS.IA32e on VMentry.
                vmx_write(VMCS_GUEST_IA32_EFER, efer | Efer_lma_bit);
              }
            else if (cr4 & Cr4_pae_bit) // && !EFER.LME
                trace().printf("Enable PAE paging.\n");
            else
                trace().printf("Enable 32-bit paging\n");
          }

        // disable paging
        if (!(newval & Cr0_pg_bit) && (old_cr0 & Cr0_pg_bit))
          {
            trace().printf("Disabling paging ...\n");

            vmx_write(VMCS_VM_ENTRY_CTLS,
                      vmx_read(VMCS_VM_ENTRY_CTLS) & ~Entry_ctrl_ia32e_bit);
            // Contrary to SDM Vol 3, 24.8.1. IA32_EFER.LMA is not set to
            // the value of ENTRY_CTLS.IA32e on VMentry.
            vmx_write(VMCS_GUEST_IA32_EFER, efer & ~Efer_lma_bit);
          }

        // 0x10 => Extension Type; hardcoded to 1 see manual
        vmx_write(VMCS_GUEST_CR0, newval | 0x10);
        vmx_write(VMCS_CR0_READ_SHADOW, newval);
        break;
      }
    case 4:
      {
        trace().printf("mov to cr4: 0x%lx, RIP 0x%lx\n", newval, ip());
        l4_uint64_t old_cr4 = vmx_read(VMCS_GUEST_CR4);

        if (vmx_read(VMCS_GUEST_CR0) & Cr0_pg_bit)
          {
            if ((newval & Cr4_la57_bit) != (old_cr4 & Cr4_la57_bit))
              {
                // inject GPF and do not write CR4
                return General_protection;
              }

            l4_uint64_t efer = vmx_read(VMCS_GUEST_IA32_EFER);
            if (!(newval & Cr4_pae_bit) && (efer & Efer_lme_bit))
              {
                // inject GPF and do not write CR4
                return General_protection;
              }
            // !EFER.LME means either PAE or 32-bit paging. Transitioning
            // between these two while Cr0.PG is set is allowed.
          }

        // We don't support 5-level page tables, be quirky and don't allow
        // setting this bit. (Or fix page-table walker.)
        if (newval & Cr4_la57_bit)
          {
            info().printf("Cr4 Guest wants to enable LA57. Filtering...\n");
            newval &= ~Cr4_la57_bit;
          }

        // CR4 0x2000  = VMXEnable bit
        // force VMXEnable bit, but hide it from guest
        vmx_write(VMCS_GUEST_CR4, newval | 0x2000);
        vmx_write(VMCS_CR4_READ_SHADOW, newval);
        break;
      }

    default:
      warn().printf("Unknown CR access.\n");
      return -L4_EINVAL;
    }

  return Jump_instr;
}

int
Vmx_state::handle_hardware_exception(Event_recorder *ev_rec, unsigned num,
                                     l4_uint32_t err_code)
{
  if (in_real_mode())
    {
      // In real mode, exceptions do not push an error code.
      ev_rec->make_add_event<Real_mode_exc>(Event_prio::Exception, num);
      return Retry;
    }

  // Reflect all hardware exceptions to the guest. Exceptions pushing an error
  // code are handled specially.
  switch (num)
    {
    case 8:  // #DF
    case 10: // #TS
    case 11: // #NP
    case 12: // #SS
    case 13: // #GP
    case 14: // #PF
    case 17: // #AC
    case 21: // #CP
      ev_rec->make_add_event<Event_exc>(Event_prio::Exception, num, err_code);
      break;

    case 1: // #DB
      // #DB exceptions are either of fault type or of trap type. We reflect
      // both to the guest, without changing state, thus don't change the IP.
      // Fall-through
    default:
      ev_rec->make_add_event<Event_exc>(Event_prio::Exception, num);
      break;
    }

  return Retry;
}

bool
Vmx_state::in_real_mode() const
{
  return (vmx_read(VMCS_GUEST_CR0) & Cr0_pe_bit) == 0;
}

} //namespace Vmm
