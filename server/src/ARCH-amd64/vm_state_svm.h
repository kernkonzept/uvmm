/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */
#pragma once

#include <l4/sys/vm>

#include <l4/cxx/bitfield>

#include "vm_state.h"
#include "debug.h"
#include "pt_walker.h"
#include "event_recorder.h"

namespace Vmm {

class Svm_state : public Vm_state
{
public:
  enum Cpuid_svm
  {
    /// Indicates support for NEXT_RIP save on #VMEXIT.
    Cpuid_svm_feature_nrips          = 1UL << 3,
    /// Indicates support for the decode assists.
    Cpuid_svm_feature_decode_assists = 1UL << 7,
  };

  enum class Exit
  {
    Cr0_read = 0x00, // Cr_access
    Cr15_read = 0x0f, // Cr_access
    Cr0_write = 0x10, // Cr_access
    Cr15_write = 0x1f, // Cr_access
    Dr0_read = 0x20,   // DR access
    Dr1_read,
    Dr2_read,
    Dr3_read,
    Dr4_read,
    Dr5_read,
    Dr6_read,
    Dr7_read,
    Dr8_read,
    Dr9_read,
    Dr10_read,
    Dr11_read,
    Dr12_read,
    Dr13_read,
    Dr14_read,
    Dr15_read = 0x2f,  // DR access
    Dr0_write = 0x30,  // DR access
    Dr1_write,
    Dr2_write,
    Dr3_write,
    Dr4_write,
    Dr5_write,
    Dr6_write,
    Dr7_write,
    Dr8_write,
    Dr9_write,
    Dr10_write,
    Dr11_write,
    Dr12_write,
    Dr13_write,
    Dr14_write,
    Dr15_write = 0x3f, // DR access
    Excp_0 = 0x40, // Exception_or_nmi
    Excp_31 = 0x5f, // Exception_or_nmi
    Intr = 0x60, // ??? Physical interrupt (maskable) -> directly handled by Fiasco!
    Nmi = 0x61, // ??? Exception_or_nmi
    Vintr = 0x64, // ??? Virtual interrupt
    Cr0_sel_write = 0x65, // Cr_access
    Rdpmc = 0x6f,  // RDPMC instruction
    Cpuid = 0x72, // Cpuid
    Sw_int = 0x75, // INTn instruction
    Hlt = 0x78, // Exec_halt
    Ioio = 0x7b, // Io_access
    Msr = 0x7c, // Exec_rdmsr and Exec_wrmsr
    Shutdown = 0x7f, // Shutdown event
    Vmrun = 0x80,   // VMRUN instruction
    Vmmcall = 0x81, // Exec_vmcall
    Vmload = 0x82,  // VMLOAD instruction
    Vmsave = 0x83,  // VMSAVE instruction
    Stgi = 0x84,    // STGI instruction
    Clgi = 0x85,    // CLGI instruction
    Skinit = 0x86,    // SKINIT instruction
    Rdtscp = 0x87,    // RDTSCP instruction
    Icebp = 0x88, // INT1 instruction
    Xsetbv = 0x8d, // Exec_xsetbv, write to xcr0 field in guest_state
    Cr0_write_trap = 0x90, // Cr_access
    Cr15_write_trap = 0x9f, // Cr_access

    Nested_page_fault = 0x400, // Ept_violation

    // TODO: intercept FERR_FREEZE event
    // TODO: intercept INTR/NMI/SMI/INIT
    // TODO: intercept INVD
    // TODO: intercept task switch
    // TODO: intercept iopm and msrpm
    // TODO: intercept MONITOR/MWAIT
    // TODO: intercept #AC and #DB (expections)
  };

  enum Intercept_inst0
  {
    Intercept_intr          = 1 << 0,
    Intercept_nmi           = 1 << 1,
    Intercept_smi           = 1 << 2,
    Intercept_init          = 1 << 3,
    Intercept_vintr         = 1 << 4,
    Intercept_cr0_sel_write = 1 << 5,
    Intercept_rdpmc         = 1 << 15,
    Intercept_cpuid         = 1 << 18,
    Intercept_invd          = 1 << 22,
    Intercept_hlt           = 1 << 24,
    Intercept_ioio          = 1 << 27,
    Intercept_msr           = 1 << 28,
    Intercept_task_switch   = 1 << 29,
    Intercept_freeze        = 1 << 30,
    Intercept_shutdown      = 1 << 31,
  };

  enum Intercept_inst1
  {
    Intercept_vmrun           = 1 << 0,
    Intercept_vmmcall         = 1 << 1,
    Intercept_vmload          = 1 << 2,
    Intercept_vmsave          = 1 << 3,
    Intercept_stgi            = 1 << 4,
    Intercept_clgi            = 1 << 5,
    Intercept_skinit          = 1 << 6,
    Intercept_rdtscp          = 1 << 7,
    Intercept_icebp           = 1 << 8,
    Intercept_wbinvd_wbnoinvd = 1 << 9,
    Intercept_monitor         = 1 << 10,
    Intercept_mwait           = 1 << 11,
    Intercept_mwait_mon       = 1 << 12,
    Intercept_xsetbv          = 1 << 13,
    Intercept_rdpru           = 1 << 14,
    Intercept_efer_write      = 1 << 15,
    Intercept_cr0_cr15_write  = 0xffff << 16,
  };

  enum Efer
  {
    Efer_lme         = 1 << 8,
    Efer_lma         = 1 << 10,
    Efer_svme_enable = 1 << 12,

    // TODO: Efer has some additional bits above on AMD
    Efer_guest_write_mask = 0xd01,
  };

  enum Cr0 : unsigned long
  {
    Cr0_pe = 1UL << 0,
    Cr0_pg = 1UL << 31,
  };

  enum Decode_assist : unsigned long long
  {
    Cr_gpr_mask = 0xf,
    Cr_valid    = 1ULL << 63,
  };

  enum Flags : unsigned long
  {
    Interrupt_enabled = (1UL << 9),
    Virtual_8086_mode = (1UL << 17),
  };

  struct Io_info
  {
    l4_uint32_t raw;
    explicit Io_info(l4_uint32_t val) : raw(val) {}

    CXX_BITFIELD_MEMBER( 0,  0, type, raw);
    CXX_BITFIELD_MEMBER( 2,  2, str, raw);
    CXX_BITFIELD_MEMBER( 3,  3, rep, raw);
    CXX_BITFIELD_MEMBER( 4,  4, sz8, raw);
    CXX_BITFIELD_MEMBER( 5,  5, sz16, raw);
    CXX_BITFIELD_MEMBER( 6,  6, sz32, raw);
    CXX_BITFIELD_MEMBER( 7,  7, a16, raw);
    CXX_BITFIELD_MEMBER( 8,  8, a32, raw);
    CXX_BITFIELD_MEMBER( 9,  9, a64, raw);
    CXX_BITFIELD_MEMBER( 4,  6, data_size, raw);
    CXX_BITFIELD_MEMBER( 7,  9, addr_size, raw);
    CXX_BITFIELD_MEMBER(10, 12, seg, raw);
    CXX_BITFIELD_MEMBER(16, 31, port, raw);
  };

  struct Npf_info
  {
    l4_uint64_t raw;
    explicit Npf_info(l4_uint64_t val) : raw(val) {}

    CXX_BITFIELD_MEMBER(0, 0, present, raw);
    CXX_BITFIELD_MEMBER(1, 1, write, raw);
    CXX_BITFIELD_MEMBER(2, 2, user, raw);
    CXX_BITFIELD_MEMBER(4, 4, inst, raw);
  };

  struct Interrupt_ctl
  {
    l4_uint64_t raw;
    explicit Interrupt_ctl(l4_uint64_t val) : raw(val) {}

    CXX_BITFIELD_MEMBER( 0,  7, v_tpr, raw);
    CXX_BITFIELD_MEMBER( 8,  8, v_irq, raw);
    CXX_BITFIELD_MEMBER(16, 19, v_intr_prio, raw);
    CXX_BITFIELD_MEMBER(20, 20, v_ign_tpr, raw);
    CXX_BITFIELD_MEMBER(32, 39, v_intr_vector, raw);
  };

  Svm_state(void *vmcb) : _vmcb(static_cast<l4_vm_svm_vmcb_t *>(vmcb)) {}
  ~Svm_state() = default;

  Type type() const override
  { return Type::Svm; }

  enum Clean_bits
  {
    Vmcb_i    = 1 << 0,  // Intercepts: all the intercept vectors, TSC offset, Pause Filter Count
    Vmcb_iopm = 1 << 1,  // IOMSRPM: IOPM_BASE, MSRPM_BASE
    Vmcb_asid = 1 << 2,  // ASID
    Vmcb_tpr  = 1 << 3,  // V_TPR, V_IRQ, V_INTR_PRIO, V_IGN_TPR, V_INTR_MASKING, V_INTR_VECTOR (Offset 60h–67h)
    Vmcb_np   = 1 << 4,  // Nested Paging: NCR3, PAT, Nested_Paging_En
    Vmcb_crx  = 1 << 5,  // CR0, CR3, CR4, EFER
    Vmcb_drx  = 1 << 6,  // DR6, DR7
    Vmcb_dt   = 1 << 7,  // GDT/IDT Limit and Base
    Vmcb_seg  = 1 << 8,  // CS/DS/SS/ES Sel/Base/Limit/Attr, CPL
    Vmcb_cr2  = 1 << 9,  // CR2
    Vmcb_lbr  = 1 << 10, // DbgCtlMsr, br_from/to, lastint_from/to
    Vmcb_avic = 1 << 11, // AVIC APIC_BAR; AVIC APIC_BACKING_PAGE, AVIC PHYSICAL_TABLE and AVIC LOGICAL_TABLE Pointers
  };

  void mark_all_clean()
  { _vmcb->control_area.clean_bits = ~0U; }

  void mark_all_dirty()
  { _vmcb->control_area.clean_bits = 0U; }

  void mark_dirty(Clean_bits bits)
  { _vmcb->control_area.clean_bits &= ~bits; }

  void init_state() override;
  void setup_linux_protected_mode(l4_addr_t entry) override;
  void setup_real_mode(l4_addr_t entry) override;

  Injection_event pending_event_injection() override
  {
    return Injection_event(_vmcb->control_area.exitintinfo);
  }

  void invalidate_pending_event()
  {
    _vmcb->control_area.exitintinfo &=
      ~(1 << Injection_event::valid_bfm_t::Lsb);
  }

  bool pf_write() const override
  { return Npf_info(_vmcb->control_area.exitinfo1).write(); }

  l4_umword_t ip() const override
  { return _vmcb->state_save_area.rip; }

  l4_umword_t sp() const override
  { return _vmcb->state_save_area.rsp; }

  l4_umword_t cr3() const override
  { return _vmcb->state_save_area.cr3; }

  l4_uint64_t xcr0() const override
  { return _vmcb->state_save_area.xcr0; }

  bool determine_next_ip_from_ip(l4_vcpu_regs_t *regs, unsigned char *inst_buf,
                                 unsigned inst_buf_len);

  void jump_instruction()
  {
    if (_vmcb->control_area.n_rip == 0)
      warn().printf("Next instruction pointer is zero: rip=0x%llx -> nrip=0x%llx\n",
                    _vmcb->state_save_area.rip, _vmcb->control_area.n_rip);

    _vmcb->state_save_area.rip = _vmcb->control_area.n_rip;
  }

  Exit exit_code() const
  { return Exit(_vmcb->control_area.exitcode); }

  l4_uint64_t exit_info1() const
  { return _vmcb->control_area.exitinfo1; }

  l4_uint64_t exit_info2() const
  { return _vmcb->control_area.exitinfo2; }

  l4_vm_svm_vmcb_t *vmcb() const
  { return _vmcb; }

  bool is_halted() const
  { return halted; }

  void halt()
  { halted = true; }

  void resume()
  { halted = false; }

  bool interrupts_enabled() const
  {
    // TODO: Instead we could use interrupt_shadow bit 1 here = GUEST_INTERRUPT_MASK
    return (_vmcb->state_save_area.rflags & Interrupt_enabled)
           && !(_vmcb->control_area.interrupt_shadow & 1);
  }

  void clear_sti_shadow()
  { _vmcb->control_area.interrupt_shadow &= (-1ULL << 1); }

  /**
   * Check if there is an event currently being injected.
   *
   * \return true  iff an event is in the process of being injected
   */
  bool event_injected() const
  { return Svm_event_info(_vmcb->control_area.eventinj).valid(); }

  /**
   * This function checks if interrupts are enabled and no event injection is
   * in flight.
   *
   * \return true  iff we can inject in an interrupt into the guest
   */
  bool can_inject_interrupt() const override
  { return interrupts_enabled() && !event_injected(); }

  void disable_interrupt_window() override
  {
    // Disable dummy virtual interrupt
    Interrupt_ctl int_ctl(_vmcb->control_area.interrupt_ctl);
    int_ctl.v_irq() = 0;
    int_ctl.v_ign_tpr() = 0;
    _vmcb->control_area.interrupt_ctl = int_ctl.raw;
    mark_dirty(Vmcb_tpr);
  }

  void enable_interrupt_window() override
  {
    // Add dummy virtual interrupt, so that we get notified via the VINTR
    // intercept, once the guest is ready to receive interrupts.
    Interrupt_ctl int_ctl(_vmcb->control_area.interrupt_ctl);
    int_ctl.v_irq() = 1;
    int_ctl.v_intr_vector() = 0;
    int_ctl.v_ign_tpr() = 1;
    _vmcb->control_area.interrupt_ctl = int_ctl.raw;
    mark_dirty(Vmcb_tpr);
  }


  /**
   * Injecting NMIs is currently not supported on SVM, as in case something
   * prevents an NMI from being injected (for example interrupt shadow), we
   * would have to single-step the guest until the NMI injection is possible.
   * In addition, we would have to intercept IRET to track NMI completion.
   *
   * Starting with Zen4, AMD SVM supports VNMI for efficient injection of NMIs.
   */
  bool can_inject_nmi() const override
  { /* TODO */ return false; }

  void disable_nmi_window() override
  { /* TODO */ }

  void enable_nmi_window() override
  { /* TODO */ }

  struct Svm_event_info
  {
    enum class Int_type : unsigned
    {
      External_interrupt = 0,
      NMI = 2,
      Exception = 3,
      Software_interrupt = 4,
    };

    l4_uint64_t field;
    CXX_BITFIELD_MEMBER(0, 7, vector, field);
    CXX_BITFIELD_MEMBER(8, 10, type, field);
    CXX_BITFIELD_MEMBER(11, 11, error_valid, field);
    CXX_BITFIELD_MEMBER(31, 31, valid, field);
    CXX_BITFIELD_MEMBER(32, 63, error_code, field);

    Svm_event_info(l4_uint64_t raw) : field(raw) {}

    Svm_event_info(unsigned i, Int_type t, unsigned err_valid = 0,
                       l4_uint32_t err_code = 0, unsigned v = 1)
    : field(0)
    {
      vector() = i;
      type() = static_cast<unsigned>(t);
      error_valid() = err_valid;
      valid() = v;
      error_code() = err_code;
    }
  };

  enum Deliver_error_code : unsigned
  {
    No_error_code = 0,
    Push_error_code = 1,
  };

  void inject_event(Injection_event const &ev) override
  {
    assert(ev.valid());
    _vmcb->control_area.eventinj = ev.raw;
  }

  void inject_event(int event_num, Svm_event_info::Int_type type,
                    Deliver_error_code deliver_err = No_error_code,
                    l4_uint32_t err_code = 0)
  {
    Svm_event_info info(event_num, type, deliver_err, err_code);

    if (0)
      warn().printf(
        "-------------- Injecting interrupt/event 0x%x -> (0x%llx)\n",
        event_num, info.field);

    _vmcb->control_area.eventinj = info.field;
  }

  int handle_cr0_write(l4_vcpu_regs_t *regs);
  int handle_xsetbv(l4_vcpu_regs_t *regs);

  bool read_msr(unsigned msr, l4_uint64_t *value) const override;
  bool write_msr(unsigned msr, l4_uint64_t value, Event_recorder *) override;

  int handle_hardware_exception(Event_recorder *ev_rec, unsigned num);

  l4_umword_t read_gpr(l4_vcpu_regs_t *regs, unsigned reg) const;

  static const char *str_exit_code(Exit exit);

  void dump(l4_vcpu_regs_t const *regs) const;

  void advance_entry_ip(unsigned bytes) override
  { _vmcb->control_area.n_rip += bytes; }

  void additional_failure_info(unsigned /* vcpu_id */) {}

private:
  static Dbg warn()
  { return Dbg(Dbg::Cpu, Dbg::Warn, "SVM"); }

  static Dbg info()
  { return Dbg(Dbg::Cpu, Dbg::Info, "SVM"); }

  static Dbg trace()
  { return Dbg(Dbg::Cpu, Dbg::Trace, "SVM"); }

  l4_vm_svm_vmcb_t *_vmcb;
  bool halted = false;
};

} // namespace Vmm
