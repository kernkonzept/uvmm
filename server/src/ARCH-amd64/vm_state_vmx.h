/* * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <tuple>
#include <l4/sys/vm>

#include <l4/cxx/bitfield>
#include <l4/vcpu/vmx/vmcs.h>

#include "vm_state.h"
#include "guest.h"
#include "debug.h"

namespace Vmm {

class Vmx_state : public Vm_state
{
public:
  enum class Exit {
      Exception_or_nmi = 0,
      External_int = 1,
      Triple_fault = 2,
      Init_signal = 3,
      Sipi = 4,
      Io_smi = 5,
      Other_smi = 6,
      Interrupt_window = 7,
      Nmi_window = 8,
      Task_switch = 9,
      Cpuid = 10,
      Getsec = 11,
      Exec_halt = 12,
      Exec_invalid = 13,
      Exec_invlpg = 14,
      Exec_rdpmc = 15,
      Exec_rdtsc = 16,
      Exec_rsm = 17,
      Exec_vmcall = 18,
      Exec_vmclear = 19,
      Exec_vmlaunch = 20,
      Exec_vmptrld = 21,
      Exec_vmptrst = 22,
      Exec_vmread = 23,
      Cr_access = 28,
      Io_access = 30,
      Exec_rdmsr = 31,
      Exec_wrmsr = 32,
      Invalid_guest = 33,
      Apic_access = 44,
      Virtualized_eoi = 45,
      Ept_violation = 48,
      Exec_xsetbv = 55,
      Apic_write = 56,
      Exit_reason_max = 64
  };

  enum Vmx_primary_vm_execution_controls : unsigned long
  {
    Int_window_exit_bit = (1UL << 2),
    Hlt_exit_bit = (1UL << 7),
    Tpr_shadow_bit = (1UL << 21),
    Enable_secondary_ctls_bit = (1UL << 31),
  };

  enum Vmx_secondary_vm_execution_controls : unsigned long
  {
    Virt_apic_access_bit = 1UL,
    Ept_enable_bit = (1UL << 1),
    X2apic_virt_bit = (1UL << 4),
    Apic_reg_virt_bit = (1UL << 8),
    Apic_virt_int_bit = (1UL << 9),
  };

  enum Vmx_exit_execution_controls : unsigned long
  {
    Ack_interrupt_on_exit_bit = (1UL << 15),
  };

  enum Flags_bits : unsigned long
  {
    Interrupt_enabled_bit = (1UL << 9),
    Virtual_8086_mode_bit = (1UL << 17),
  };

  enum Vmx_vm_entry_ctls : unsigned long
  {
    Vm_entry_load_ia32_efer = (1UL << 15),
  };

  enum Vmx_vm_exit_ctls : unsigned long
  {
    Vm_exit_save_ia32_efer = (1UL << 20),
    Vm_exit_load_ia32_efer = (1UL << 21),
  };

  Vmx_state(void *vmcs) : _vmcs(vmcs) {}
  ~Vmx_state() = default;

  void init_state() override
  {
    vmx_write(L4VCPU_VMCS_LINK_POINTER, 0xffffffffffffffffULL);
    vmx_write(L4VCPU_VMCS_GUEST_ACTIVITY_STATE, 0);
    vmx_write(L4VCPU_VMCS_EXCEPTION_BITMAP, 0xffffffff &~ (1<<14));

    vmx_write(L4VCPU_VMCS_VM_ENTRY_CTLS,
              vmx_read(L4VCPU_VMCS_VM_ENTRY_CTLS) | Vm_entry_load_ia32_efer);

    vmx_write(L4VCPU_VMCS_VM_EXIT_CTLS,
              vmx_read(L4VCPU_VMCS_VM_EXIT_CTLS)
              | Vm_exit_save_ia32_efer
              | Vm_exit_load_ia32_efer);

  }

  bool pf_write() const override
  { return vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION) & 0x2; }

  l4_umword_t ip() const override
  { return l4_vm_vmx_read_nat(_vmcs, L4VCPU_VMCS_GUEST_RIP); }

  l4_umword_t cr3() const override
  { return l4_vm_vmx_read_nat(_vmcs, L4VCPU_VMCS_GUEST_CR3); }

  void jump_instruction() override
  {
    vmx_write(L4VCPU_VMCS_GUEST_RIP,
              vmx_read(L4VCPU_VMCS_GUEST_RIP)
                + vmx_read(L4VCPU_VMCS_VM_EXIT_INSN_LENGTH));
  }

  void setup_protected_mode(l4_addr_t entry) override
  {
    vmx_write(L4VCPU_VMCS_GUEST_CS_SELECTOR, 0x10);
    vmx_write(L4VCPU_VMCS_GUEST_CS_ACCESS_RIGHTS, 0xd09b);
    vmx_write(L4VCPU_VMCS_GUEST_CS_LIMIT, 0xffffffff);
    vmx_write(L4VCPU_VMCS_GUEST_CS_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_SS_SELECTOR, 0x18);
    vmx_write(L4VCPU_VMCS_GUEST_SS_ACCESS_RIGHTS, 0xc093);
    vmx_write(L4VCPU_VMCS_GUEST_SS_LIMIT, 0xffffffff);
    vmx_write(L4VCPU_VMCS_GUEST_SS_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_DS_SELECTOR, 0x18);
    vmx_write(L4VCPU_VMCS_GUEST_DS_ACCESS_RIGHTS, 0xc093);
    vmx_write(L4VCPU_VMCS_GUEST_DS_LIMIT, 0xffffffff);
    vmx_write(L4VCPU_VMCS_GUEST_DS_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_ES_SELECTOR, 0x18);
    vmx_write(L4VCPU_VMCS_GUEST_ES_ACCESS_RIGHTS, 0xc093);
    vmx_write(L4VCPU_VMCS_GUEST_ES_LIMIT, 0xffffffff);
    vmx_write(L4VCPU_VMCS_GUEST_ES_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_FS_SELECTOR, 0x0);
    vmx_write(L4VCPU_VMCS_GUEST_FS_ACCESS_RIGHTS, 0x1c0f3);
    vmx_write(L4VCPU_VMCS_GUEST_FS_LIMIT, 0xffffffff);
    vmx_write(L4VCPU_VMCS_GUEST_FS_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_GS_SELECTOR, 0x0);
    vmx_write(L4VCPU_VMCS_GUEST_GS_ACCESS_RIGHTS, 0x1c0f3);
    vmx_write(L4VCPU_VMCS_GUEST_GS_LIMIT, 0xffffffff);
    vmx_write(L4VCPU_VMCS_GUEST_GS_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_LDTR_SELECTOR, 0x0);
    vmx_write(L4VCPU_VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
    vmx_write(L4VCPU_VMCS_GUEST_LDTR_LIMIT, 0);
    vmx_write(L4VCPU_VMCS_GUEST_LDTR_BASE, 0);

    vmx_write(L4VCPU_VMCS_GUEST_TR_SELECTOR, 0x28);
    vmx_write(L4VCPU_VMCS_GUEST_TR_ACCESS_RIGHTS, 0x108b);
    vmx_write(L4VCPU_VMCS_GUEST_TR_LIMIT, 67);
    vmx_write(L4VCPU_VMCS_GUEST_TR_BASE, 0);

    vmx_write(L4VCPU_VMCS_VM_ENTRY_CTLS,
              vmx_read(L4VCPU_VMCS_VM_ENTRY_CTLS) &~ (1 << 9)); // disable long mode

    l4_umword_t eflags;
    asm volatile("pushf     \n"
                 "pop %0   \n"
                 : "=r" (eflags));

    eflags &= ~Interrupt_enabled_bit;
    eflags &= ~Virtual_8086_mode_bit;

    vmx_write(L4VCPU_VMCS_GUEST_RIP, entry);
    vmx_write(L4VCPU_VMCS_GUEST_RFLAGS, eflags);
    vmx_write(L4VCPU_VMCS_GUEST_RSP, 0);
    vmx_write(L4VCPU_VMCS_GUEST_CR0, 0x1003b);
    vmx_write(L4VCPU_VMCS_CR0_READ_SHADOW, 0x1003b);
    vmx_write(L4VCPU_VMCS_CR0_GUEST_HOST_MASK, ~0ULL);

    vmx_write(L4VCPU_VMCS_GUEST_CR3, 0);
    vmx_write(L4VCPU_VMCS_GUEST_CR4, 0x2690);
    vmx_write(L4VCPU_VMCS_CR4_READ_SHADOW, 0x0690);
    vmx_write(L4VCPU_VMCS_CR4_GUEST_HOST_MASK, ~0ULL);
    vmx_write(L4VCPU_VMCS_GUEST_DR7, 0x300);
    vmx_write(L4VCPU_VMCS_GUEST_IA32_EFER, 0x0);

    vmx_write(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                | Int_window_exit_bit
                | Hlt_exit_bit
                | Enable_secondary_ctls_bit
              );


    vmx_write(L4VCPU_VMCS_SEC_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(L4VCPU_VMCS_SEC_PROC_BASED_VM_EXEC_CTLS)
                | Ept_enable_bit
              );

  }

  Exit exit_reason() const
  {
    return Exit(vmx_read(L4VCPU_VMCS_EXIT_REASON) & 0xffffU);
  }

  unsigned msr_shadow_reg(l4_umword_t msr)
  {
    switch (msr)
    {
      case 0x00000174: return L4VCPU_VMCS_GUEST_IA32_SYSENTER_CS;
      case 0x00000175: return L4VCPU_VMCS_GUEST_IA32_SYSENTER_ESP;
      case 0x00000176: return L4VCPU_VMCS_GUEST_IA32_SYSENTER_EIP;
      case 0xc0000081: return L4_VM_VMX_VMCS_MSR_STAR;
      case 0xc0000082: return L4_VM_VMX_VMCS_MSR_LSTAR;
      case 0xc0000083: return L4_VM_VMX_VMCS_MSR_CSTAR;
      case 0xc0000084: return L4_VM_VMX_VMCS_MSR_SYSCALL_MASK;
#ifdef ARCH_amd64
      case 0xc0000100: return L4VCPU_VMCS_GUEST_FS_BASE;
      case 0xc0000101: return L4VCPU_VMCS_GUEST_GS_BASE;
      case 0xc0000102: return L4_VM_VMX_VMCS_MSR_KERNEL_GS_BASE;
#endif
      default: return 0;
    }
  }

  bool interrupts_enabled() const override
  {
    return (vmx_read(L4VCPU_VMCS_GUEST_RFLAGS) & Interrupt_enabled_bit)
           && (vmx_read(L4VCPU_VMCS_GUEST_INTERRUPTIBILITY_STATE) == 0);
  }

  void disable_interrupt_window() override
  {
    vmx_write(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                & ~Int_window_exit_bit);
  }

  void enable_interrupt_window() override
  {
    vmx_write(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                | Int_window_exit_bit);
  }

  /**
   * The interrupt information for VM entry and exit have the same layout. Some
   * fields are used only for event injection on entry and some are only used
   * during interrupt exit. See the Intel manual for details: 24.8.3, 24.9.2.
   */
  struct Vmx_int_info_field
  {
    enum class Int_type : unsigned {
        External_interrupt = 0,
        NMI = 2,
        Hardware_exception = 3,
        Software_interrupt = 4,
        Priviledged_sw_exception = 5,
        Software_exception = 6,
        Other_event = 7,
    };

    l4_uint32_t field;
    CXX_BITFIELD_MEMBER(0, 7, vector, field);
    CXX_BITFIELD_MEMBER(8, 10, type, field);
    CXX_BITFIELD_MEMBER(11, 11, error_valid, field);
    CXX_BITFIELD_MEMBER(12, 12, nmi_iret, field); // VM exit info only.
    CXX_BITFIELD_MEMBER(13, 30, reserved, field);
    CXX_BITFIELD_MEMBER(31, 31, valid, field);

    Vmx_int_info_field(l4_uint32_t raw) : field(raw) {}

    Vmx_int_info_field(unsigned i, Int_type t, unsigned err_valid = 0,
                       unsigned v = 1)
    : field(0)
    {
      vector().set(i);
      type().set(static_cast<unsigned>(t));
      error_valid().set(err_valid);
      valid().set(v);
    }
  };

  void inject_event(int event_num, Vmx_int_info_field::Int_type type)
  {
    Vmx_int_info_field info(event_num, type);

    if (0)
      Dbg(Dbg::Guest, Dbg::Warn)
        .printf(
          "-------------- Injecting interrupt/event 0x%x (%p) -> (0x%x)\n",
          event_num,
          l4_vm_vmx_field_ptr(_vmcs, L4VCPU_VMCS_VM_ENTRY_INTERRUPT_INFO),
          info.field);

    vmx_write(L4VCPU_VMCS_VM_ENTRY_INTERRUPT_INFO, info.field);
    if (vmx_read(L4VCPU_VMCS_GUEST_ACTIVITY_STATE) == 1) // HLT
      {
        vmx_write(L4VCPU_VMCS_GUEST_ACTIVITY_STATE, 0);
      }
  }

  void inject_interrupt(unsigned irq) override
  {
    using Int_type = Vmx_int_info_field::Int_type;
    inject_event(irq, Int_type::External_interrupt);
  }

  void inject_hw_exception(int exc_num)
  {
    using Int_type = Vmx_int_info_field::Int_type;
    inject_event(exc_num, Int_type::Hardware_exception);
  }

  void unhalt() override
  {
    jump_instruction();
    // XXX should we verify that the processor is in HLT state?
    vmx_write(L4VCPU_VMCS_GUEST_ACTIVITY_STATE, 0);
  }

  l4_uint64_t vmx_read(unsigned int field) const
  { return l4_vm_vmx_read(_vmcs, field); }

  void vmx_write(unsigned field, l4_uint64_t val)
  { l4_vm_vmx_write(_vmcs, field, val); }

  virtual void dump_state() const override
  {
    Dbg dbg(Dbg::Guest, Dbg::Warn);
    dbg.printf("========= Dumping VMCS state ============\n");
    dbg.printf("(C) VPID: 0x%llx\n", vmx_read(L4VCPU_VMCS_VPID));
    dbg.printf("(C) Int notification vector: 0x%llx\n", vmx_read(L4VCPU_VMCS_PIR_NOTIFICATION_VECTOR));
    dbg.printf("(C) EPTP index: 0x%llx\n", vmx_read(L4VCPU_VMCS_EPTP_INDEX));
    dbg.printf("(C) EPT pointer: 0x%llx\n", vmx_read(L4VCPU_VMCS_EPT_POINTER));
    dbg.printf("(C) Pin-based execution control: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_PIN_BASED_VM_EXEC_CTLS));
    dbg.printf("(C) Primary execution control: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_PRI_PROC_BASED_VM_EXEC_CTLS));
    dbg.printf("(C) Secondary execution control: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_SEC_PROC_BASED_VM_EXEC_CTLS));
    void *ext = (void *)((char *) _vmcs - 0x400);
    dbg.printf("(C) Basic capabilities: 0x%llx\n",
               l4_vm_vmx_get_caps(ext, L4_VM_VMX_BASIC_REG));
    dbg.printf("(C) Real pin-based execution control: 0x%llx\n",
               l4_vm_vmx_get_caps(ext, L4_VM_VMX_TRUE_PINBASED_CTLS_REG));
    dbg.printf("(C) Real primary execution control: 0x%llx\n",
               l4_vm_vmx_get_caps(ext, L4_VM_VMX_TRUE_PROCBASED_CTLS_REG));
    dbg.printf("(C) Real secondary execution control: 0x%llx\n",
               l4_vm_vmx_get_caps(ext, L4_VM_VMX_PROCBASED_CTLS2_REG));

    dbg.printf("(G) ES selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_ES_SELECTOR));
    dbg.printf("(G) CS selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_CS_SELECTOR));
    dbg.printf("(G) SS selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_SS_SELECTOR));
    dbg.printf("(G) DS selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_DS_SELECTOR));
    dbg.printf("(G) FS selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_FS_SELECTOR));
    dbg.printf("(G) GS selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_GS_SELECTOR));
    dbg.printf("(G) LDTR selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_LDTR_SELECTOR));
    dbg.printf("(G) TR selector: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_TR_SELECTOR));
    dbg.printf("(G) interrupt status: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_INTERRUPT_STATUS));

    dbg.printf("(C) IO bitmap A: 0x%llx\n", vmx_read(L4VCPU_VMCS_ADDRESS_IO_BITMAP_A));
    dbg.printf("(C) IO bitmap B: 0x%llx\n", vmx_read(L4VCPU_VMCS_ADDRESS_IO_BITMAP_B));
    dbg.printf("(C) MSR bitmaps: 0x%llx\n", vmx_read(L4VCPU_VMCS_ADDRESS_MSR_BITMAP));
    dbg.printf("(C) Exit MSR store address: 0x%llx\n",
           vmx_read(L4VCPU_VMCS_VM_EXIT_MSR_STORE_ADDRESS));
    dbg.printf("(C) Exit MSR load address: 0x%llx\n",
           vmx_read(L4VCPU_VMCS_VM_EXIT_MSR_LOAD_ADDRESS));
    dbg.printf("(C) Entry MSR load address: 0x%llx\n",
           vmx_read(L4VCPU_VMCS_VM_ENTRY_MSR_LOAD_ADDRESS));
    dbg.printf("(G) Guest IA32 EFER: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_IA32_EFER));

    dbg.printf("(C) Entry control: 0x%llx\n", vmx_read(L4VCPU_VMCS_VM_ENTRY_CTLS));
    dbg.printf("(C) Entry error: 0x%llx\n", vmx_read(L4VCPU_VMCS_VM_ENTRY_EXCEPTION_ERROR));
    dbg.printf("(C) VM-instruction error: 0x%llx\n", vmx_read(L4VCPU_VMCS_VM_INSN_ERROR));
    dbg.printf("(C) Entry MSR load cnt: 0x%llx\n", vmx_read(L4VCPU_VMCS_VM_ENTRY_MSR_LOAD_COUNT));
    dbg.printf("(C) Exit control: 0x%llx\n", vmx_read(L4VCPU_VMCS_VM_EXIT_CTLS));
    dbg.printf("(C) Exit reason: 0x%llx\n", vmx_read(L4VCPU_VMCS_EXIT_REASON));
    dbg.printf("(C) Entry interupt info: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_VM_ENTRY_INTERRUPT_INFO));
    dbg.printf("(C) Exit interupt info: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_VM_EXIT_INTERRUPT_INFO));
    dbg.printf("(C) Guest interruptability: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_GUEST_INTERRUPTIBILITY_STATE));

    dbg.printf("(G) ES limit: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_ES_LIMIT));
    dbg.printf("(G) CS limit: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_CS_LIMIT));
    dbg.printf("(G) SS limit: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_SS_LIMIT));
    dbg.printf("(G) DS limit: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_DS_LIMIT));
    dbg.printf("(G) FS limit: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_FS_LIMIT));
    dbg.printf("(G) GS limit: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_GS_LIMIT));
    dbg.printf("(G) Activity state: 0x%llx\n",
               vmx_read(L4VCPU_VMCS_GUEST_ACTIVITY_STATE));

    dbg.printf("(G) sysenter rip: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_IA32_SYSENTER_EIP));
    dbg.printf("(G) sysenter rsp: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_IA32_SYSENTER_ESP));
    dbg.printf("(G) exit qualification: 0x%llx\n", vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION));
    dbg.printf("(G) guest linear address: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_LINEAR_ADDRESS));
    dbg.printf("(G) CR0: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_CR0));
    dbg.printf("(G) CR3: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_CR3));
    dbg.printf("(G) CR4: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_CR4));
    dbg.printf("(G) RFLAGS: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_RFLAGS));
    dbg.printf("(G) RIP: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_RIP));
    dbg.printf("(G) RSP: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_RSP));
    dbg.printf("(G) ES base: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_ES_BASE));
    dbg.printf("(G) CS base: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_CS_BASE));
    dbg.printf("(G) SS base: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_SS_BASE));
    dbg.printf("(G) DS base: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_DS_BASE));
    dbg.printf("(G) FS base: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_FS_BASE));
    dbg.printf("(G) GS base: 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_GS_BASE));
    dbg.printf("(G) EFER   : 0x%llx\n", vmx_read(L4VCPU_VMCS_GUEST_IA32_EFER));

    dbg.printf("=========================================\n");
  }

  int handle_cr_access(l4_vcpu_regs_t *regs);
  int handle_exception_nmi_ext_int();
  int handle_exec_rmsr(l4_vcpu_regs_t *regs, Gic::Virt_lapic *apic);
  int handle_exec_wmsr(l4_vcpu_regs_t *regs, Gic::Virt_lapic *apic);
  int handle_hardware_exception(unsigned num);

private:
  void *_vmcs;
};

} // namespace Vmm
