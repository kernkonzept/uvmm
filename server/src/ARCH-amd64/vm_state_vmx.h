/* * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/vm>

#include <l4/cxx/bitfield>

#include "vmcs.h"
#include "vm_state.h"
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
    Unrestricted_guest_bit = (1UL << 7),
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
    Ia32e_mode_guest = (1UL << 9),
  };

  enum Vmx_vm_exit_ctls : unsigned long
  {
    Vm_exit_save_ia32_efer = (1UL << 20),
    Vm_exit_load_ia32_efer = (1UL << 21),
    Host_address_space_size = (1UL << 9),
  };

  Vmx_state(void *vmcs) : _vmcs(vmcs) {}
  ~Vmx_state() = default;

  void init_state() override
  {
    vmx_write(VMCS_LINK_POINTER, 0xffffffffffffffffULL);
    vmx_write(VMCS_GUEST_ACTIVITY_STATE, 0);
    // reflect all guest exceptions back to the guest.
    vmx_write(VMCS_EXCEPTION_BITMAP, 0xffff0000);

    vmx_write(VMCS_VM_ENTRY_CTLS,
              (vmx_read(VMCS_VM_ENTRY_CTLS)
                | Vm_entry_load_ia32_efer)
                & ~Ia32e_mode_guest); // disable long mode

    vmx_write(VMCS_VM_EXIT_CTLS,
              vmx_read(VMCS_VM_EXIT_CTLS)
              | Vm_exit_save_ia32_efer
              | Vm_exit_load_ia32_efer
              | Host_address_space_size);

    vmx_write(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                | Int_window_exit_bit
                | Hlt_exit_bit
                | Enable_secondary_ctls_bit
              );

    vmx_write(VMCS_SEC_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_SEC_PROC_BASED_VM_EXEC_CTLS)
                | Ept_enable_bit
                | Unrestricted_guest_bit
              );

    vmx_write(VMCS_GUEST_LDTR_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
    vmx_write(VMCS_GUEST_LDTR_LIMIT, 0);
    vmx_write(VMCS_GUEST_LDTR_BASE, 0);

    l4_umword_t eflags;
    asm volatile("pushf     \n"
                 "pop %0   \n"
                 : "=r" (eflags));
    eflags &= ~Interrupt_enabled_bit;
    eflags &= ~Virtual_8086_mode_bit;
    vmx_write(VMCS_GUEST_RFLAGS, eflags);

    vmx_write(VMCS_GUEST_CR3, 0);
    vmx_write(VMCS_GUEST_DR7, 0x300);
    vmx_write(VMCS_GUEST_IA32_EFER, 0x0);
  }

  bool pf_write() const override
  { return vmx_read(VMCS_EXIT_QUALIFICATION) & 0x2; }

  l4_umword_t ip() const override
  { return l4_vm_vmx_read_nat(_vmcs, VMCS_GUEST_RIP); }

  l4_umword_t cr3() const override
  { return l4_vm_vmx_read_nat(_vmcs, VMCS_GUEST_CR3); }

  void jump_instruction() override
  {
    vmx_write(VMCS_GUEST_RIP,
              vmx_read(VMCS_GUEST_RIP)
                + vmx_read(VMCS_VM_EXIT_INSN_LENGTH));
  }

  void setup_protected_mode(l4_addr_t entry) override
  {
    vmx_write(VMCS_GUEST_CS_SELECTOR, 0x10);
    vmx_write(VMCS_GUEST_CS_ACCESS_RIGHTS, 0xd09b);
    vmx_write(VMCS_GUEST_CS_LIMIT, 0xffffffff);
    vmx_write(VMCS_GUEST_CS_BASE, 0);

    vmx_write(VMCS_GUEST_SS_SELECTOR, 0x18);
    vmx_write(VMCS_GUEST_SS_ACCESS_RIGHTS, 0xc093);
    vmx_write(VMCS_GUEST_SS_LIMIT, 0xffffffff);
    vmx_write(VMCS_GUEST_SS_BASE, 0);

    vmx_write(VMCS_GUEST_DS_SELECTOR, 0x18);
    vmx_write(VMCS_GUEST_DS_ACCESS_RIGHTS, 0xc093);
    vmx_write(VMCS_GUEST_DS_LIMIT, 0xffffffff);
    vmx_write(VMCS_GUEST_DS_BASE, 0);

    vmx_write(VMCS_GUEST_ES_SELECTOR, 0x18);
    vmx_write(VMCS_GUEST_ES_ACCESS_RIGHTS, 0xc093);
    vmx_write(VMCS_GUEST_ES_LIMIT, 0xffffffff);
    vmx_write(VMCS_GUEST_ES_BASE, 0);

    vmx_write(VMCS_GUEST_FS_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_FS_ACCESS_RIGHTS, 0x1c0f3);
    vmx_write(VMCS_GUEST_FS_LIMIT, 0xffffffff);
    vmx_write(VMCS_GUEST_FS_BASE, 0);

    vmx_write(VMCS_GUEST_GS_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_GS_ACCESS_RIGHTS, 0x1c0f3);
    vmx_write(VMCS_GUEST_GS_LIMIT, 0xffffffff);
    vmx_write(VMCS_GUEST_GS_BASE, 0);

    vmx_write(VMCS_GUEST_TR_SELECTOR, 0x28);
    vmx_write(VMCS_GUEST_TR_ACCESS_RIGHTS, 0x108b);
    vmx_write(VMCS_GUEST_TR_LIMIT, 67);
    vmx_write(VMCS_GUEST_TR_BASE, 0);

    vmx_write(VMCS_GUEST_RIP, entry);
    vmx_write(VMCS_GUEST_RSP, 0);
    vmx_write(VMCS_GUEST_CR0, 0x10031);
    vmx_write(VMCS_CR0_READ_SHADOW, 0x10031);
    vmx_write(VMCS_CR0_GUEST_HOST_MASK, ~0ULL);

    vmx_write(VMCS_GUEST_CR4, 0x2690);
    vmx_write(VMCS_CR4_READ_SHADOW, 0x0690);
    vmx_write(VMCS_CR4_GUEST_HOST_MASK, ~0ULL);
  }

  /**
   * Setup Application Processors in Real Mode.
   *
   * The entry page is set up using the Code Segment because Linux uses an
   * entry page address larger than 16 bits, hence the 20 bit Segment Base is
   * set up according to Vol. 3B, 20.1.1 Figure 20-1 and the instruction
   * pointer is set to zero.
   */
  void setup_real_mode(l4_addr_t entry) override
  {
    // 9.9.2 Switching Back to Real-Address Mode
    vmx_write(VMCS_GUEST_CS_SELECTOR, (entry >> 4));
    // 3.4.5 Segment Descriptors
    vmx_write(VMCS_GUEST_CS_ACCESS_RIGHTS, 0x9b);
    vmx_write(VMCS_GUEST_CS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_CS_BASE, entry);

    vmx_write(VMCS_GUEST_SS_SELECTOR, 0x18);
    vmx_write(VMCS_GUEST_SS_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_SS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_SS_BASE, 0);

    vmx_write(VMCS_GUEST_DS_SELECTOR, 0x18);
    vmx_write(VMCS_GUEST_DS_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_DS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_DS_BASE, 0);

    vmx_write(VMCS_GUEST_ES_SELECTOR, 0x18);
    vmx_write(VMCS_GUEST_ES_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_ES_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_ES_BASE, 0);

    vmx_write(VMCS_GUEST_FS_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_FS_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_FS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_FS_BASE, 0);

    vmx_write(VMCS_GUEST_GS_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_GS_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_GS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_GS_BASE, 0);

    vmx_write(VMCS_GUEST_TR_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_TR_ACCESS_RIGHTS, 0x8b);
    vmx_write(VMCS_GUEST_TR_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_TR_BASE, 0);

    vmx_write(VMCS_GUEST_RIP, 0);
    vmx_write(VMCS_GUEST_RSP, 0);
    vmx_write(VMCS_GUEST_CR0, 0x10030);
    vmx_write(VMCS_CR0_READ_SHADOW, 0x10030);
    vmx_write(VMCS_CR0_GUEST_HOST_MASK, ~0ULL);

    vmx_write(VMCS_GUEST_CR4, 0x2680);
    vmx_write(VMCS_CR4_READ_SHADOW, 0x0680);
    vmx_write(VMCS_CR4_GUEST_HOST_MASK, ~0ULL);
  }

  Exit exit_reason() const
  {
    return Exit(vmx_read(VMCS_EXIT_REASON) & 0xffffU);
  }

  unsigned msr_shadow_reg(l4_umword_t msr) const
  {
    switch (msr)
    {
      case 0x00000174: return VMCS_GUEST_IA32_SYSENTER_CS;
      case 0x00000175: return VMCS_GUEST_IA32_SYSENTER_ESP;
      case 0x00000176: return VMCS_GUEST_IA32_SYSENTER_EIP;
      case 0xc0000081: return L4_VM_VMX_VMCS_MSR_STAR;
      case 0xc0000082: return L4_VM_VMX_VMCS_MSR_LSTAR;
      case 0xc0000083: return L4_VM_VMX_VMCS_MSR_CSTAR;
      case 0xc0000084: return L4_VM_VMX_VMCS_MSR_SYSCALL_MASK;
#ifdef ARCH_amd64
      case 0xc0000100: return VMCS_GUEST_FS_BASE;
      case 0xc0000101: return VMCS_GUEST_GS_BASE;
      case 0xc0000102: return L4_VM_VMX_VMCS_MSR_KERNEL_GS_BASE;
#endif
      default: return 0;
    }
  }

  bool interrupts_enabled() const override
  {
    return (vmx_read(VMCS_GUEST_RFLAGS) & Interrupt_enabled_bit)
           && (vmx_read(VMCS_GUEST_INTERRUPTIBILITY_STATE) == 0);
  }

  /**
   * Check if there is an event currently being injected.
   *
   * This could happen, e.g. if the vmx_resume was interrupted before entering
   * the guest.
   *
   * \return true  iff an event is in the process of being injected
   */
  bool event_injected() const
  {
    return Vmx_int_info_field(vmx_read(VMCS_VM_ENTRY_INTERRUPT_INFO)
                              & ((1ULL << 32) - 1)).valid();
  }

  /**
   * This function checks if interrupts are enabled and no event injection is
   * in flight.
   *
   * \return true  iff we can inject in an interrupt into the guest
   */
  bool can_inject_interrupt() const
  {
    return interrupts_enabled() && !event_injected();
  }

  void disable_interrupt_window() override
  {
    vmx_write(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                & ~Int_window_exit_bit);
  }

  void enable_interrupt_window() override
  {
    vmx_write(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
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

  enum Deliver_error_code : unsigned
  {
    No_error_code = 0,
    Push_error_code = 1,
  };

  void inject_event(int event_num, Vmx_int_info_field::Int_type type,
                    Deliver_error_code deliver_err = No_error_code,
                    l4_uint32_t err_code = 0)
  {
    Vmx_int_info_field info(event_num, type, deliver_err);

    if (0)
      warn().printf(
        "-------------- Injecting interrupt/event 0x%x (%p) -> (0x%x)\n",
        event_num,
        l4_vm_vmx_field_ptr(_vmcs, VMCS_VM_ENTRY_INTERRUPT_INFO),
        info.field);

    if (deliver_err == Push_error_code)
      vmx_write(VMCS_VM_ENTRY_EXCEPTION_ERROR, err_code);

    vmx_write(VMCS_VM_ENTRY_INTERRUPT_INFO, info.field);
    if (vmx_read(VMCS_GUEST_ACTIVITY_STATE) == 1) // HLT
      {
        vmx_write(VMCS_GUEST_ACTIVITY_STATE, 0);
      }
  }

  void inject_interrupt(unsigned irq) override
  {
    using Int_type = Vmx_int_info_field::Int_type;
    inject_event(irq, Int_type::External_interrupt);
  }

  /**
   * Inject a hardware description into the guest.
   *
   * \param exec_num     Exception number.
   * \param deliver_err  Deliver error code on the guest stack.
   * \param err_code     Error code to deliver, if any.
   */
  void inject_hw_exception(int exc_num, Deliver_error_code deliver_err,
                           l4_uint32_t err_code = 0)
  {
    using Int_type = Vmx_int_info_field::Int_type;
    inject_event(exc_num, Int_type::Hardware_exception, deliver_err, err_code);
  }

  void unhalt() override
  {
    jump_instruction();
    // XXX should we verify that the processor is in HLT state?
    vmx_write(VMCS_GUEST_ACTIVITY_STATE, 0);
  }

  l4_uint64_t vmx_read(unsigned int field) const
  { return l4_vm_vmx_read(_vmcs, field); }

  void vmx_write(unsigned field, l4_uint64_t val)
  { l4_vm_vmx_write(_vmcs, field, val); }

  int handle_cr_access(l4_vcpu_regs_t *regs);
  int handle_exception_nmi_ext_int();

  bool read_msr(unsigned msr, l4_uint64_t *value) const override;
  bool write_msr(unsigned msr, l4_uint64_t value) override;

  int handle_hardware_exception(unsigned num);

private:
  static Dbg warn()
  { return Dbg(Dbg::Cpu, Dbg::Warn); }

  static Dbg info()
  { return Dbg(Dbg::Cpu, Dbg::Info); }

  static Dbg trace()
  { return Dbg(Dbg::Cpu, Dbg::Trace); }

  void *_vmcs;
};

} // namespace Vmm
