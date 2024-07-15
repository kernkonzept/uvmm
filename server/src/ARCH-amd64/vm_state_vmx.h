/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */

#pragma once

#include <l4/re/error_helper>
#include <l4/re/util/unique_cap>
#include <l4/sys/vm>

#include <l4/cxx/bitfield>

#include "vmcs.h"
#include "vm_state.h"
#include "debug.h"
#include "event_recorder.h"

#include <cstdio>

#include <cassert>

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
      Exec_getsec = 11,
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
      Exec_vmresume = 24,
      Exec_vmwrite = 25,
      Exec_vmxoff = 26,
      Exec_vmxon = 27,
      Cr_access = 28,
      Mov_debug_reg = 29,
      Io_access = 30,
      Exec_rdmsr = 31,
      Exec_wrmsr = 32,
      Entry_fail_invalid_guest = 33,
      Entry_fail_msr = 34,
      // 35 unused
      Exec_mwait = 36,
      Monitor_trap_flag = 37,
      // 38 unused
      Exec_monitor = 39,
      Exec_pause = 40,
      Entry_fail_machine_check = 41,
      // 42 unsued
      Tpr_threshold = 43,
      Apic_access = 44,
      Virtualized_eoi = 45,
      Access_gdtr_idtr = 46,
      Access_ldtr_tr = 47,
      Ept_violation = 48,
      Ept_misconfig = 49,
      Exec_invept = 50,
      Exec_rdtscp = 51,
      Vmx_preempt_timer = 52,
      Exec_invvpid = 53,
      Exec_wbinvd = 54,
      Exec_xsetbv = 55,
      Apic_write = 56,
      Exec_rdrand = 57,
      Exec_invpcid = 58,
      Vmfunc = 59,
      Exec_encls = 60,
      Exec_rdseed = 61,
      Page_mod_log_full = 62,
      Exec_xsaves = 63,
      Exec_xrstors = 64,
      // 65 unused
      Spp_related_event = 66,
      Exec_umwait = 67,
      Exec_tpause = 68,
      Exec_loadiwkey = 69,
      Exit_reason_max
  };

  enum Activity_state : unsigned
  {
    Active = 0,
    Halt = 1,
    Shutdown = 2,
    Wait_sipi = 3
  };

  enum Vmx_pin_based_vm_execution_controls : unsigned
  {
    Ext_int_exiting_bit = (1U << 0),
    Nmi_exiting_bit = (1U << 3),
    Virtual_nmis_bit = (1U << 5),
    Activate_vmx_preemption_timer_bit = (1U << 6),
    Process_posted_ints = (1U << 7),
  };

  enum Vmx_primary_vm_execution_controls : unsigned long
  {
    Int_window_exit_bit = (1UL << 2),
    Hlt_exit_bit = (1UL << 7),
    Rdpmc_exit_bit = (1UL << 11),
    Tpr_shadow_bit = (1UL << 21),
    Nmi_window_exit_bit = (1UL << 22),
    Mov_dr_exit_bit = (1UL << 23),
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
    Vm_entry_load_ia32_pat = (1UL << 14),
    Vm_entry_load_ia32_efer = (1UL << 15),
    Ia32e_mode_guest = (1UL << 9),
  };

  enum Vmx_vm_exit_ctls : unsigned long
  {
    Vm_exit_save_ia32_pat = (1UL << 18),  ///< save guest PAT
    Vm_exit_load_ia32_pat = (1UL << 19),  ///< load host PAT
    Vm_exit_save_ia32_efer = (1UL << 20), ///< save guest EFER
    Vm_exit_load_ia32_efer = (1UL << 21), ///< load host EFER
    Host_address_space_size = (1UL << 9),
  };

  Vmx_state(void *vmcs);
  ~Vmx_state() = default;

  Type type() const override
  { return Type::Vmx; }

  void set_activity_state(Activity_state s)
  { vmx_write(VMCS_GUEST_ACTIVITY_STATE, s); }

  l4_uint32_t activity_state() const
  { return vmx_read(VMCS_GUEST_ACTIVITY_STATE); }

  void init_state() override
  {
    set_hw_vmcs();

    // The reset values are taken from Intel SDM Vol.3 10.1.1;
    set_activity_state(Active);
    // reflect all guest exceptions back to the guest.
    vmx_write(VMCS_EXCEPTION_BITMAP, 0xffff0000);

    // PAT reset value
    vmx_write(VMCS_GUEST_IA32_PAT, 0x0007040600070406ULL);

    // XCR0 reset value;
    vmx_write(L4_VM_VMX_VMCS_XCR0, 0x1ULL);

    vmx_write(VMCS_PIN_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PIN_BASED_VM_EXEC_CTLS)
              | Nmi_exiting_bit
              | Virtual_nmis_bit);

    vmx_write(VMCS_VM_ENTRY_CTLS,
              (vmx_read(VMCS_VM_ENTRY_CTLS)
               | Vm_entry_load_ia32_pat
               | Vm_entry_load_ia32_efer)
                & ~Ia32e_mode_guest); // disable long mode

    // Guest PAT & EFER are emulated on each access, no need to additionally
    // store them on VMexit.
    vmx_write(VMCS_VM_EXIT_CTLS,
              vmx_read(VMCS_VM_EXIT_CTLS)
              | Vm_exit_load_ia32_pat
              | Vm_exit_load_ia32_efer
              | Host_address_space_size);

    vmx_write(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                | Hlt_exit_bit
                | Rdpmc_exit_bit // kernel enforced. keep in sync here.
                | Mov_dr_exit_bit // kernel enforced. keep in sync here.
                | Enable_secondary_ctls_bit
              );

    vmx_write(VMCS_SEC_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_SEC_PROC_BASED_VM_EXEC_CTLS)
                | Ept_enable_bit
                | Unrestricted_guest_bit
              );

    // System descriptor described in Intel SDM Vol.3 Chapter 3.5
    vmx_write(VMCS_GUEST_LDTR_SELECTOR, 0x0);
    vmx_write(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x82);
    vmx_write(VMCS_GUEST_LDTR_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_LDTR_BASE, 0);

    vmx_write(VMCS_GUEST_RFLAGS, 0x02);

    vmx_write(VMCS_GUEST_CR3, 0);
    vmx_write(VMCS_GUEST_DR7, 0x300);
    vmx_write(VMCS_GUEST_IA32_EFER, 0x0);
  }

  bool pf_write() const override
  { return vmx_read(VMCS_EXIT_QUALIFICATION) & 0x2; }

  l4_umword_t ip() const override
  { return l4_vm_vmx_read_nat(_vmcs, VMCS_GUEST_RIP); }

  l4_umword_t sp() const override
  { return l4_vm_vmx_read_nat(_vmcs, VMCS_GUEST_RSP); }

  l4_umword_t cr3() const override
  { return l4_vm_vmx_read_nat(_vmcs, VMCS_GUEST_CR3); }

  l4_uint64_t xcr0() const override
  { return vmx_read(L4_VM_VMX_VMCS_XCR0); }

  void jump_instruction()
  {
    vmx_write(VMCS_GUEST_RIP,
              vmx_read(VMCS_GUEST_RIP)
                + vmx_read(VMCS_VM_EXIT_INSN_LENGTH));
  }

  void setup_linux_protected_mode(l4_addr_t entry) override
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
   * Setup the Real Mode startup procedure for AP startup and BSP resume.
   *
   * This follows the hardware reset behavior described in Intel SDM "10.1.4
   * First Instruction Executed".
   */
  void setup_real_mode(l4_addr_t entry) override
  {
    if (entry == 0xfffffff0U)
      {
        // Bootstrap Processor (BSP) boot
        vmx_write(VMCS_GUEST_CS_SELECTOR, 0xf000U);
        vmx_write(VMCS_GUEST_CS_BASE, 0xffff0000U);
        vmx_write(VMCS_GUEST_RIP, 0xfff0U);
      }
    else
      {
        // Application Processor (AP) boot via Startup IPI (SIPI) or resume
        // from suspend.
        // CS_BASE contains the cached address computed from CS_SELECTOR. After
        // reset CS_BASE contains what we set until the first CS SELECTOR is
      // loaded. We use the waking vector or SIPI vector directly, because
      // tianocore cannot handle the CS_BASE + IP split.
        vmx_write(VMCS_GUEST_CS_SELECTOR, entry >> 4);
        vmx_write(VMCS_GUEST_CS_BASE, entry);
        vmx_write(VMCS_GUEST_RIP, 0);
      }

    vmx_write(VMCS_GUEST_CS_ACCESS_RIGHTS, 0x9b);
    vmx_write(VMCS_GUEST_CS_LIMIT, 0xffff);

    vmx_write(VMCS_GUEST_SS_SELECTOR, 0);
    vmx_write(VMCS_GUEST_SS_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_SS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_SS_BASE, 0);

    vmx_write(VMCS_GUEST_DS_SELECTOR, 0);
    vmx_write(VMCS_GUEST_DS_ACCESS_RIGHTS, 0x93);
    vmx_write(VMCS_GUEST_DS_LIMIT, 0xffff);
    vmx_write(VMCS_GUEST_DS_BASE, 0);

    vmx_write(VMCS_GUEST_ES_SELECTOR, 0);
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

    vmx_write(VMCS_GUEST_RSP, 0);
    vmx_write(VMCS_GUEST_CR0, 0x60000010UL);
    vmx_write(VMCS_CR0_READ_SHADOW, 0x60000010UL);
    vmx_write(VMCS_CR0_GUEST_HOST_MASK, ~0ULL);

    vmx_write(VMCS_GUEST_CR4, 0x2680);
    vmx_write(VMCS_CR4_READ_SHADOW, 0x0680);
    vmx_write(VMCS_CR4_GUEST_HOST_MASK, ~0ULL);

    // clear in SW state to prevent injection of pending events from before
    // INIT/STARTUP IPI.
    vmx_write(VMCS_IDT_VECTORING_ERROR, 0ULL);
  }

  Injection_event pending_event_injection() override
  {
    Vmx_state::Idt_vectoring_info vinfo = idt_vectoring_info();
    if (vinfo.valid() && vinfo.error_valid())
      {
        return Injection_event(vinfo.field, vmx_read(VMCS_IDT_VECTORING_ERROR)
                                              & 0xffffffffUL);
      }
    else
      return Injection_event(vinfo.field, 0U);
  }

  void invalidate_pending_event()
  {
    Vmx_state::Idt_vectoring_info vinfo = idt_vectoring_info();
    if (vinfo.valid())
      {
        vinfo.valid().set(0);
        vmx_write(VMCS_IDT_VECTORING_INFO, vinfo.field);
      }
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

  bool is_halted() const
  {
    return activity_state() == Activity_state::Halt;
  }

  void halt()
  {
    set_activity_state(Vmx_state::Activity_state::Halt);
  }

  void resume()
  {
    set_activity_state(Vmx_state::Activity_state::Active);
  }

  class Interruptibility_state
  {
    l4_uint32_t _state;

  public:
    Interruptibility_state(l4_uint32_t int_state)
    : _state(int_state)
    {}

    bool irq_enabled() { return !sti() && !mov_ss() && !nmi(); }
    // STI may block NMIs as well. VMX entry may fail, so check STI bit as well.
    bool nmi_enabled() { return !sti() && !mov_ss() && !nmi(); }

    void clear_sti() { sti().set(0); }

    l4_uint32_t state() const { return _state; }

    CXX_BITFIELD_MEMBER(0, 0, sti, _state);
    CXX_BITFIELD_MEMBER(1, 1, mov_ss, _state);
    CXX_BITFIELD_MEMBER(2, 2, smi, _state);
    CXX_BITFIELD_MEMBER(3, 3, nmi, _state);
    CXX_BITFIELD_MEMBER(4, 4, enclave, _state);
  };

  Interruptibility_state interrupt_state() const
  { return Interruptibility_state(vmx_read(VMCS_GUEST_INTERRUPTIBILITY_STATE)); }

  bool interrupts_enabled() const
  {
    return (vmx_read(VMCS_GUEST_RFLAGS) & Interrupt_enabled_bit)
           && interrupt_state().irq_enabled();
  }

  /**
   * Clear the STI interrupt shadow in the interruptibility state.
   *
   * This must be called when we emulate an instruction to ensure subsequent
   * event injection can happen.
   */
  void clear_sti_shadow()
  {
    auto int_state = interrupt_state();
    if (!int_state.sti())
      return;

    int_state.clear_sti();
    vmx_write(VMCS_GUEST_INTERRUPTIBILITY_STATE, int_state.state());
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
    return entry_int_info().valid();
  }

  /**
   * This function checks if interrupts are enabled and no event injection is
   * in flight and the core's activity state allows interrupts.
   *
   * \return true  iff we can inject in an interrupt into the guest
   */
  bool can_inject_interrupt() const override
  {
    return interrupts_enabled() && !event_injected()
           && activity_state() < Activity_state::Shutdown;
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

  bool can_inject_nmi() const override
  {
    return interrupt_state().nmi_enabled()
           && !event_injected()
           && activity_state() < Activity_state::Shutdown;
  }

  void disable_nmi_window() override
  {
    vmx_write(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                & ~Nmi_window_exit_bit);
  }

  void enable_nmi_window() override
  {
    vmx_write(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS,
              vmx_read(VMCS_PRI_PROC_BASED_VM_EXEC_CTLS)
                | Nmi_window_exit_bit);
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

  /**
   * Structure representing the VM Exit Instruction Information.
   *
   * Note that the instruction information defines different valid bitfields
   * for different instructions, but the location of those bitfields is mostly
   * consistent.
   */
  struct Vmx_insn_info_field
  {
    l4_uint32_t field;
    CXX_BITFIELD_MEMBER(0, 1, scaling, field);
    // Bit 2 is undefined.
    CXX_BITFIELD_MEMBER(3, 6, gpr, field);
    CXX_BITFIELD_MEMBER(7, 9, address_size, field);
    CXX_BITFIELD_MEMBER(10, 10, mem_reg, field);
    CXX_BITFIELD_MEMBER(11, 12, operand_size, field);
    // Bit 13 is undefined.
    // Bit 14 is undefined.
    CXX_BITFIELD_MEMBER(15, 17, segment, field);
    CXX_BITFIELD_MEMBER(18, 21, index, field);
    CXX_BITFIELD_MEMBER(22, 22, index_valid_bit, field);
    CXX_BITFIELD_MEMBER(23, 26, base, field);
    CXX_BITFIELD_MEMBER(27, 27, base_valid_bit, field);
    CXX_BITFIELD_MEMBER(28, 31, gpr2, field);

    Vmx_insn_info_field() = delete;
    Vmx_insn_info_field(l4_uint32_t raw) : field(raw) {}

    bool index_valid() const
    { return index_valid_bit() == 0; }

    bool base_valid() const
    { return base_valid_bit() == 0; }
  };

  /// Type alias to handle VM-exit interrupt data.
  using Vm_exit_int_info = Vmx_int_info_field;
  /// Type alias to handle VM-entry event injection data.
  using Vm_entry_int_info = Vmx_int_info_field;
  /// Type alias to handle event data stored in IDT-vectoring information.
  using Idt_vectoring_info = Vmx_int_info_field;

  /// Get VM-exit interrupt information data.
  Vm_exit_int_info exit_int_info() const
  { return Vm_exit_int_info(vmx_read(VMCS_VM_EXIT_INTERRUPT_INFO)); }

  /// Get the current VM-entry interrupt information data.
  Vm_entry_int_info entry_int_info() const
  { return Vm_entry_int_info(vmx_read(VMCS_VM_ENTRY_INTERRUPT_INFO)); }

  /// Get a description of the VMCS' IDT-vectoring information field.
  Idt_vectoring_info idt_vectoring_info() const
  { return Idt_vectoring_info(vmx_read(VMCS_IDT_VECTORING_INFO)); }

  /**
   * Inject an event stored in IDT-vectoring information format.
   *
   * \param info  IDT-vectoring information field value.
   */
  void inject_event(Idt_vectoring_info const &info)
  {
    assert(info.valid());

    vmx_write(VMCS_VM_ENTRY_INTERRUPT_INFO, info.field);
    if (info.error_valid())
      vmx_write(VMCS_VM_ENTRY_EXCEPTION_ERROR,
                vmx_read(VMCS_IDT_VECTORING_ERROR));
  }

  void inject_event(Injection_event const &ev) override
  {
    assert(ev.valid());

    vmx_write(VMCS_VM_ENTRY_INTERRUPT_INFO, ev.event());
    if (ev.error_valid())
      vmx_write(VMCS_VM_ENTRY_EXCEPTION_ERROR, ev.error());
  }

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
  }

  l4_uint64_t vmx_read(unsigned int field) const
  { return l4_vm_vmx_read(_vmcs, field); }

  void vmx_write(unsigned field, l4_uint64_t val)
  { l4_vm_vmx_write(_vmcs, field, val); }

  void set_hw_vmcs()
  {
    l4_vm_vmx_set_hw_vmcs(_vmcs, _hw_vmcs.cap());
  }

  int handle_cr_access(l4_vcpu_regs_t *regs);
  int handle_exception_nmi_ext_int(Event_recorder *ev_rec);

  bool read_msr(unsigned msr, l4_uint64_t *value) const override;
  bool write_msr(unsigned msr, l4_uint64_t value, Event_recorder *ev_rec) override;

  int handle_hardware_exception(Event_recorder *ev_rec, unsigned num,
                                l4_uint32_t err_code);

  void advance_entry_ip(unsigned bytes) override
  { vmx_write(VMCS_VM_ENTRY_INSN_LEN, bytes); }

  void additional_failure_info(unsigned vcpu_id)
  {
    Err().printf("[%3u] VM instruction error: 0x%llx\n", vcpu_id,
                 vmx_read(VMCS_VM_INSN_ERROR));
  }

private:
  using Hw_vmcs = L4Re::Util::Unique_cap<L4::Vcpu_context>;

  static Dbg warn()
  { return Dbg(Dbg::Cpu, Dbg::Warn, "VMX"); }

  static Dbg info()
  { return Dbg(Dbg::Cpu, Dbg::Info, "VMX"); }

  static Dbg trace()
  { return Dbg(Dbg::Cpu, Dbg::Trace, "VMX"); }

  /**
   * Check that the guest is running in real mode.
   *
   * \retval true   Guest is running in real mode.
   * \retval false  Guest is not running in real mode.
   */
  bool in_real_mode() const;

  void *_vmcs;
  Hw_vmcs _hw_vmcs;
};

} // namespace Vmm
