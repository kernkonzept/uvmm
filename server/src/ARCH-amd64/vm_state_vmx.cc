/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "vm_state_vmx.h"
#include "consts.h"

namespace Vmm {

Vm_state::~Vm_state() = default;

enum : unsigned long
  {
    Cr0_pe_bit = 1UL,
    Cr0_pg_bit = 1UL << 31,

    Efer_lme_bit = 1UL << 8,
    Efer_lma_bit = 1UL << 10,

    Entry_ctrl_ia32e_bit = 1UL << 9,
  };

/**
 * Handle exits due to HW/SW exceptions, NMIs, and external interrupts.
 *
 * Bit 11, error_valid, is not set if, an external interrupt occurred and
 * 'acknowledge interrupt on exit' the is not set in the exit controls.
 */
int
Vmx_state::handle_exception_nmi_ext_int()
{
  auto interrupt_info = Vmx_int_info_field(
    (l4_uint32_t)vmx_read(VMCS_VM_EXIT_INTERRUPT_INFO));

  l4_uint32_t interrupt_error = 0;
  if (interrupt_info.error_valid())
    interrupt_error =
      (l4_uint32_t)vmx_read(VMCS_VM_EXIT_INTERRUPT_ERROR);

  info().printf("Interrupt exit: 0x%x/0x%x\n", interrupt_info.field,
                (unsigned)interrupt_error);

  switch ((interrupt_info.type()))
    {
    case 0x6:
      warn().printf("Software exception %u\n",
                    (unsigned)interrupt_info.vector());
      break;
    case 0x3:
      return handle_hardware_exception(interrupt_info.vector());

    case 0x2: warn().printf("NMI\n"); break;
    case 0x0: warn().printf("External interrupt\n"); break;
    default: warn().printf("Unknown\n"); break;
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
        case 0x8b: // IA32_BIOS_SIGN_ID
        case 0x1a0: // IA32_MISC_ENABLE
          *value = 0U;
          break;
        case 0x3a: // IA32_FEATURE_CONTROL
          // Lock register so the guest does not try to enable anything.
          *value = 1U;
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
Vmx_state::write_msr(unsigned msr, l4_uint64_t value)
{
  unsigned shadow = msr_shadow_reg(msr);
  if (shadow > 0)
    {
      vmx_write(shadow, value);
      return true;
    }

  switch (msr)
    {
    case 0xc0000080: // efer
      {
        l4_uint64_t efer = value & 0xD01;
        auto vm_entry_ctls = vmx_read(VMCS_VM_ENTRY_CTLS);

        trace().printf("vmx read CRO: 0x%llx old efer 0x%llx new efer 0x%llx, "
                       "vm_entry_ctls 0x%llx\n",
                       vmx_read(VMCS_GUEST_CR0),
                       vmx_read(VMCS_GUEST_IA32_EFER), efer,
                       vm_entry_ctls);

        if ((efer & Efer_lme_bit)
            && (vmx_read(VMCS_GUEST_CR0) & Cr0_pg_bit))
          {
            // enable long mode
            vmx_write(VMCS_VM_ENTRY_CTLS,
                      vm_entry_ctls | Entry_ctrl_ia32e_bit);
            efer |= Efer_lma_bit;
          }
        else // There is no going back from enabling long mode.
          {
            if (efer & Efer_lme_bit)
              {
                if (vm_entry_ctls & Entry_ctrl_ia32e_bit)
                  efer |= Efer_lma_bit;
              }
          }
        trace().printf("efer: 0x%llx, vm_entry_ctls 0x%llx\n", efer,
                       vm_entry_ctls);
        vmx_write(VMCS_GUEST_IA32_EFER, efer);
        break;
      }
    case 0x8b: // IA32_BIOS_SIGN_ID
    case 0x140:  // unknown in Intel 6th gen, but MISC_FEATURE register for xeon
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
        // 0x10 => Extension Type; hardcoded to 1 see manual
        vmx_write(VMCS_GUEST_CR0, newval | 0x10);
        vmx_write(VMCS_CR0_READ_SHADOW, newval);
        if ((newval & Cr0_pg_bit)
            && (old_cr0 & Cr0_pg_bit) == 0
            && (vmx_read(VMCS_GUEST_IA32_EFER) & Efer_lme_bit))
          {
            // enable long mode
            info().printf("Enable long mode\n");
            vmx_write(VMCS_VM_ENTRY_CTLS,
                      vmx_read(VMCS_VM_ENTRY_CTLS)
                        | Entry_ctrl_ia32e_bit);
            vmx_write(VMCS_GUEST_IA32_EFER,
                      vmx_read(VMCS_GUEST_IA32_EFER) | Efer_lma_bit);
          }

        if ((newval & Cr0_pg_bit) == 0
            && (old_cr0 & Cr0_pg_bit))
          {
            trace().printf("Disabling paging ...\n");
            vmx_write(VMCS_VM_ENTRY_CTLS,
                      vmx_read(VMCS_VM_ENTRY_CTLS)
                        & ~Entry_ctrl_ia32e_bit);

            if (vmx_read(VMCS_GUEST_IA32_EFER) & Efer_lme_bit)
              vmx_write(VMCS_GUEST_IA32_EFER,
                        vmx_read(VMCS_GUEST_IA32_EFER) & ~Efer_lma_bit);
          }

        break;
      }
    case 4:
      // force VMXE bit but hide it from guest
      trace().printf("mov to cr4: 0x%lx, RIP 0x%lx\n", newval, ip());
      // CR4 0x2000  = VMXEnable bit
      vmx_write(VMCS_GUEST_CR4, newval | 0x2000);
      vmx_write(VMCS_CR4_READ_SHADOW, newval);
      break;
    default: warn().printf("Unknown CR access.\n"); return -L4_EINVAL;
    }
  return Jump_instr;
}

int
Vmx_state::handle_hardware_exception(unsigned num)
{
  Err err;
  err.printf("Hardware exception\n");

  switch (num)
  {
    case 0: err.printf("Divide error\n"); break;
    case 1: err.printf("Debug\n"); break;
    case 3: err.printf("Breakpoint\n"); break;
    case 4: err.printf("Overflow\n"); break;
    case 5: err.printf("Bound range\n"); break;
    case 6: err.printf("Invalid opcode\n"); break;
    case 7: err.printf("Device not available\n"); break;
    case 8: err.printf("Double fault\n"); break;
    case 9: err.printf("Coprocessor segment overrun\n"); break;
    case 10: err.printf("Invalid TSS\n"); break;
    case 11: err.printf("Segment not present\n"); break;
    case 12: err.printf("Stack-segment fault\n"); break;
    case 13: err.printf("General protection\n"); break;
    case 14: err.printf("Page fault\n"); break;
    case 16: err.printf("FPU error\n"); break;
    case 17: err.printf("Alignment check\n"); break;
    case 18: err.printf("Machine check\n"); break;
    case 19: err.printf("SIMD error\n"); break;
    default: err.printf("Unknown exception\n"); break;
  }
  return -L4_EINVAL;
}

} //namespace Vmm
