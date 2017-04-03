/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "vm_state_vmx.h"
#include "mem_access.h"
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
    (l4_uint32_t)vmx_read(L4VCPU_VMCS_VM_EXIT_INTERRUPT_INFO));

  l4_uint32_t interrupt_error = 0;
  if (interrupt_info.error_valid())
    interrupt_error =
      (l4_uint32_t)vmx_read(L4VCPU_VMCS_VM_EXIT_INTERRUPT_ERROR);

  Dbg().printf("Interrupt exit: 0x%x/0x%x\n", interrupt_info.field,
               (unsigned)interrupt_error);

  switch ((interrupt_info.type()))
    {
    case 0x6: Dbg().printf("Software exception\n"); break;
    case 0x3:
      return handle_hardware_exception(interrupt_info.vector());

    case 0x2: Dbg().printf("NMI\n"); break;
    case 0x0: Dbg().printf("External interrupt\n"); break;
    default: Dbg().printf("Unknown\n"); break;
    }
  return -L4_ENOSYS;
}

int
Vmx_state::handle_exec_rmsr(l4_vcpu_regs_t *regs,
                            Gic::Virt_lapic *apic)
{
  l4_uint64_t result = 0;
  auto msr = regs->cx;

  unsigned shadow = msr_shadow_reg(msr);
  if (shadow > 0)
    {
      result = vmx_read(shadow);
    }
  else if (!apic->read_msr(msr, &result))
    {
      switch (msr)
        {
        case 0xc0000080: // efer
          result = vmx_read(L4VCPU_VMCS_GUEST_IA32_EFER);
          break;

        default:
          Dbg().printf("Warning: reading unsupported MSR 0x%lx\n", regs->cx);
        }
    }

  regs->ax = (l4_uint32_t)result;
  regs->dx = (l4_uint32_t)(result >> 32);
  return Jump_instr;
}

int
Vmx_state::handle_exec_wmsr(l4_vcpu_regs_t *regs,
                            Gic::Virt_lapic *apic)
{
  auto msr = regs->cx;
  l4_uint64_t value =
    (l4_uint64_t(regs->ax) & 0xFFFFFFFF) | (l4_uint64_t(regs->dx) << 32);

  unsigned shadow = msr_shadow_reg(msr);
  if (shadow > 0)
    {
      vmx_write(shadow, value);
      return Jump_instr;
    }

  if (apic->write_msr(msr, value))
    return Jump_instr;

  switch (msr)
    {
    case 0xc0000080: // efer
      {
        l4_uint64_t efer = value & 0xF01;
        auto vm_entry_ctls = vmx_read(L4VCPU_VMCS_VM_ENTRY_CTLS);

        Dbg().printf("vmx read CRO: 0x%llx efer 0x%llx, vm_entry_ctls 0x%llx\n",
                     vmx_read(L4VCPU_VMCS_GUEST_CR0), efer, vm_entry_ctls);

        if ((efer & Efer_lme_bit)
            && (vmx_read(L4VCPU_VMCS_GUEST_CR0) & Cr0_pg_bit))
          {
            // enable long mode
            vmx_write(L4VCPU_VMCS_VM_ENTRY_CTLS,
                      vm_entry_ctls | Entry_ctrl_ia32e_bit);
            efer |= Efer_lma_bit;
            Dbg().printf("long mode efer\n");
          }
        else // There is no going back from enabling long mode.
          {
            if (efer & Efer_lme_bit)
              {
                if (vm_entry_ctls & Entry_ctrl_ia32e_bit)
                  efer |= Efer_lma_bit;
              }
          }
        Dbg().printf("efer: 0x%llx, vm_entry_ctls 0x%llx\n", efer,
                     vm_entry_ctls);
        vmx_write(L4VCPU_VMCS_GUEST_IA32_EFER, efer);
        return Jump_instr;
      }
    case 0x8b: // IA32_BIOS_SIGN_ID
      // can all be savely ignored
      return Jump_instr;

    default:
      Dbg().printf("FATAL: Writing unhandled MSR: 0x%lx\n", regs->cx);
      return -L4_ENOSYS;
    }
}

int
Vmx_state::handle_cr_access(l4_vcpu_regs_t *regs)
{
  auto qual = vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION);
  int crnum;
  l4_umword_t newval;

  switch ((qual >> 4) & 3)
    {
    case 0: // mov to cr
      crnum = qual & 0xF;
      Dbg().printf("mov to cr %d\n", crnum);
      switch ((qual >> 8) & 0xF)
        {
        case 0: newval = regs->ax; break;
        case 1: newval = regs->cx; break;
        case 2: newval = regs->dx; break;
        case 3: newval = regs->bx; break;
        case 4: newval = vmx_read(L4VCPU_VMCS_GUEST_RSP); break;
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
          Dbg().printf("Loading CR from unknown register\n");
          return -L4_EINVAL;
        }
      break;
    case 2: // clts
      crnum = 0;
      newval = vmx_read(L4VCPU_VMCS_GUEST_CR0) & ~(1ULL << 3);
      break;
    default:
      Dbg().printf("Unknown CR action %lld.\n", (qual >> 4) & 3);
      return -L4_EINVAL;
    }

  switch (crnum)
    {
    case 0:
      Dbg().printf("Write to cr0: 0x%lx\n", newval);
      // 0x10 => Extension Type; hardcoded to 1 see manual
      vmx_write(L4VCPU_VMCS_GUEST_CR0, newval | 0x10);
      vmx_write(L4VCPU_VMCS_CR0_READ_SHADOW, newval);
      if ((newval & Cr0_pg_bit)
          && (vmx_read(L4VCPU_VMCS_GUEST_IA32_EFER) & Efer_lme_bit))
        {
          // enable long mode
          Dbg().printf("Enable long mode\n");
          vmx_write(L4VCPU_VMCS_VM_ENTRY_CTLS,
                    vmx_read(L4VCPU_VMCS_VM_ENTRY_CTLS) | Entry_ctrl_ia32e_bit);
          vmx_write(L4VCPU_VMCS_GUEST_IA32_EFER,
                    vmx_read(L4VCPU_VMCS_GUEST_IA32_EFER) | Efer_lma_bit);
        }
      break;
    case 4:
      // force VMXE bit but hide it from guest
      Dbg().printf("mov to cr4: 0x%lx, RIP 0x%lx\n", newval, ip());
      // CR4 0x2000  = VMXEnable bit
      vmx_write(L4VCPU_VMCS_GUEST_CR4, newval | 0x2000);
      vmx_write(L4VCPU_VMCS_CR4_READ_SHADOW, newval);
      break;
    default: Dbg().printf("Unknown CR access.\n"); return -L4_EINVAL;
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
