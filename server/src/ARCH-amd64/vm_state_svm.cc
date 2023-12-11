/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include <l4/re/error_helper>

#include "vm_state_svm.h"
#include "consts.h"
#include "mad.h"

namespace Vmm {

void
Svm_state::init_state()
{
    // Does not matter, Linux overwrites it...
  _vmcb->state_save_area.ldtr.selector = 0;
  _vmcb->state_save_area.ldtr.attrib = 0;
  _vmcb->state_save_area.ldtr.limit = 0;
  _vmcb->state_save_area.ldtr.base = 0;

  // TODO: Setup GDTR, IDTR? (not done on VMX)

  // Always use nested paging!
  _vmcb->control_area.np_enable = 1;
  // Initiated to default values at reset: WB,WT,WC,UC,WB,WT,UC-,UC
  _vmcb->state_save_area.g_pat = 0x0007040600010406ULL;
  // Reset value of XCR0
  _vmcb->state_save_area.xcr0 = 1ULL;

  _vmcb->state_save_area.rflags = 0;
  _vmcb->state_save_area.cr3 = 0;
  _vmcb->state_save_area.dr6 = 0;
  _vmcb->state_save_area.dr7 = 0;

  _vmcb->control_area.eventinj = 0;

  // Enable SVM
  _vmcb->state_save_area.efer = Efer_svme_enable;

  // Intercept DR accesses.
  // The kernel enforces 0xff3f, to keep the behavior consistent with VMX, we
  // intercept all DR accesses.
  _vmcb->control_area.intercept_rd_drX = 0xffff;
  _vmcb->control_area.intercept_wr_drX = 0xffff;

  _vmcb->control_area.intercept_exceptions = 0;

  _vmcb->control_area.intercept_instruction0 =
      Intercept_intr | Intercept_nmi | Intercept_smi | Intercept_init
    | Intercept_vintr | Intercept_cr0_sel_write | Intercept_rdpmc
    | Intercept_cpuid | Intercept_invd | Intercept_hlt | Intercept_ioio
    | Intercept_msr | Intercept_task_switch | Intercept_freeze
    | Intercept_shutdown;

  // TODO: These are the instructions intercepts that Fiasco enforces. Check
  // if we intercept too less or too much...
  _vmcb->control_area.intercept_instruction1 =
      Intercept_vmrun | Intercept_vmmcall | Intercept_vmload
    | Intercept_vmsave | Intercept_stgi | Intercept_clgi | Intercept_skinit
    | Intercept_rdtscp | Intercept_monitor | Intercept_mwait
    | Intercept_xsetbv;

  mark_all_dirty();
}

void
Svm_state::setup_linux_protected_mode(l4_addr_t entry)
{
  _vmcb->state_save_area.cs.selector = 0x10;
  _vmcb->state_save_area.cs.attrib = 0xc9a; // TYPE=10=Read/Execute, S, P, DB, G
  _vmcb->state_save_area.cs.limit = 0xffffffff;
  _vmcb->state_save_area.cs.base = 0;

  _vmcb->state_save_area.ss.selector = 0x18;
  _vmcb->state_save_area.ss.attrib = 0xc92; // TYPE=2=Read/Write, S, P, DB, G
  _vmcb->state_save_area.ss.limit = 0xffffffff;
  _vmcb->state_save_area.ss.base = 0;

  _vmcb->state_save_area.ds.selector = 0x18;
  _vmcb->state_save_area.ds.attrib = 0xc92;
  _vmcb->state_save_area.ds.limit = 0xffffffff;
  _vmcb->state_save_area.ds.base = 0;

  _vmcb->state_save_area.es.selector = 0x18;
  _vmcb->state_save_area.es.attrib = 0xc92;
  _vmcb->state_save_area.es.limit = 0xffffffff;
  _vmcb->state_save_area.es.base = 0;

  _vmcb->state_save_area.fs.selector = 0x0;
  _vmcb->state_save_area.fs.attrib = 0xcf3; // Equivalent to VMX
  _vmcb->state_save_area.fs.limit = 0xffffffff;
  _vmcb->state_save_area.fs.base = 0;

  _vmcb->state_save_area.gs.selector = 0x0;
  _vmcb->state_save_area.gs.attrib = 0xcf3;
  _vmcb->state_save_area.gs.limit = 0xffffffff;
  _vmcb->state_save_area.gs.base = 0;

  _vmcb->state_save_area.tr.selector = 0x28;
  _vmcb->state_save_area.tr.attrib = 0x8b; // TYPE=11, P
  _vmcb->state_save_area.tr.limit = 0x67; // TODO: VMX uses 67 here
  _vmcb->state_save_area.tr.base = 0;

  _vmcb->state_save_area.rip = entry;
  _vmcb->state_save_area.rsp = 0;
  _vmcb->state_save_area.cr0 = 0x10031;
  _vmcb->state_save_area.cr4 = 0x690;
}

/**
 * Setup the Real Mode startup procedure for AP startup and BSP resume.
 *
 * This follows the hardware reset behavior described in AMD APM "14.1.5
 * Fetching the first instruction".
 */
void
Svm_state::setup_real_mode(l4_addr_t entry)
{
  if (entry == 0xfffffff0U)
    {
      // Bootstrap Processor (BSP) boot
      _vmcb->state_save_area.cs.selector = 0xf000U;
      _vmcb->state_save_area.cs.base = 0xffff0000U;
      _vmcb->state_save_area.rip = 0xfff0U;
    }
  else
    {
      // Application Processor (AP) boot via Startup IPI (SIPI) or resume
      // from suspend.
      // cs_base contains the cached address computed from cs_selector. After
      // reset cs_base contains what we set until the first cs selector is
      // loaded. We use the waking vector or SIPI vector directly, because
      // tianocore cannot handle the CS_BASE + IP split.
      _vmcb->state_save_area.cs.selector = entry >> 4;
      _vmcb->state_save_area.cs.base = entry;
      _vmcb->state_save_area.rip = 0;
    }

  _vmcb->state_save_area.cs.attrib = 0x9b; // TYPE=11, S, P
  _vmcb->state_save_area.cs.limit = 0xffff;

  _vmcb->state_save_area.ss.selector = 0x18;
  _vmcb->state_save_area.ss.attrib = 0x93; // TYPE=3, S, P
  _vmcb->state_save_area.ss.limit = 0xffff;
  _vmcb->state_save_area.ss.base = 0;

  _vmcb->state_save_area.ds.selector = 0x18;
  _vmcb->state_save_area.ds.attrib = 0x93;
  _vmcb->state_save_area.ds.limit = 0xffff;
  _vmcb->state_save_area.ds.base = 0;

  _vmcb->state_save_area.es.selector = 0x18;
  _vmcb->state_save_area.es.attrib = 0x93;
  _vmcb->state_save_area.es.limit = 0xffff;
  _vmcb->state_save_area.es.base = 0;

  _vmcb->state_save_area.fs.selector = 0x0;
  _vmcb->state_save_area.fs.attrib = 0x93;
  _vmcb->state_save_area.fs.limit = 0xffff;
  _vmcb->state_save_area.fs.base = 0;

  _vmcb->state_save_area.gs.selector = 0x0;
  _vmcb->state_save_area.gs.attrib = 0x93;
  _vmcb->state_save_area.gs.limit = 0xffff;
  _vmcb->state_save_area.gs.base = 0;

  _vmcb->state_save_area.tr.selector = 0x0;
  _vmcb->state_save_area.tr.attrib = 0x8b; // TYPE=11, P
  _vmcb->state_save_area.tr.limit = 0xffff;
  _vmcb->state_save_area.tr.base = 0;

  _vmcb->state_save_area.rsp = 0;
  _vmcb->state_save_area.cr0 = 0x10030;
  _vmcb->state_save_area.cr4 = 0x680;

  // clear in SW state to prevent injection of pending events from before
  // INIT/STARTUP IPI.
  _vmcb->control_area.exitintinfo = 0ULL;
}

bool
Svm_state::determine_next_ip_from_ip(l4_vcpu_regs_t *regs,
                                     unsigned char *inst_buf,
                                     unsigned inst_buf_len)
{
  using namespace L4mad;
  Op op;
  Desc tgt, src;
  Decoder decoder(reinterpret_cast<l4_exc_regs_t *>(regs), ip(), inst_buf,
                  inst_buf_len);
  if (decoder.decode(&op, &tgt, &src) != Decoder::Result::Success)
    {
      warn().printf("Could not decode instruction for current ip\n");
      return false;
    }

  trace().printf("Advance instruction pointer n_rip = 0x%lx + 0x%x\n",
                 ip(), op.insn_len);

  _vmcb->control_area.n_rip = ip() + op.insn_len;
  return true;
}

bool
Svm_state::read_msr(unsigned msr, l4_uint64_t *value) const
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
    case 0x277: // PAT
      *value =_vmcb->state_save_area.g_pat;
      break;
    case 0xc0000080: // efer
      // Hide SVME bit
      *value = _vmcb->state_save_area.efer & ~Efer_svme_enable;
      break;
    case 0xc0010140: // OSVW_ID_Length
      // TODO: Report errata to the guest? Allow direct read access to OSVW
      //       register in msrpm in Fiasco?
      *value = 0U;
      break;

    case 0xc001001f: // MSR_AMD64_NB_CFG
      // can all be savely ignored
      *value = 0;
      break;

    default:
      return false;
    }
  return true;
}

bool
Svm_state::write_msr(unsigned msr, l4_uint64_t value, Event_recorder *ev_rec)
{
  switch (msr)
    {
    case 0x277: // PAT
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

      _vmcb->state_save_area.g_pat = value;
      break;
    case 0xc0000080: // efer
      {
        // Force the SVME bit
        l4_uint64_t efer = (value & Efer_guest_write_mask) | Efer_svme_enable;
        l4_uint64_t old_efer = _vmcb->state_save_area.efer;
        l4_uint64_t cr0 = _vmcb->state_save_area.cr0;

        trace().printf("cr0: 0x%llx old efer 0x%llx new efer 0x%llx\n",
                       cr0, old_efer, efer);

        // There is no going back from enabling long mode.
        efer |= old_efer & Efer_lme;

        if ((efer & Efer_lme) && (cr0 & Cr0_pg))
          {
            // indicate that long mode is active
            efer |= Efer_lma;
          }

        trace().printf("efer: 0x%llx\n", efer);
        _vmcb->state_save_area.efer = efer;
        mark_dirty(Vmcb_crx);
        break;
      }
    case 0xc001001f: // MSR_AMD64_NB_CFG
      // can all be savely ignored
      break;

    default:
      return false;
    }

  return true;
}

int
Svm_state::handle_cr0_write(l4_vcpu_regs_t *regs)
{
  l4_uint64_t info1 = exit_info1();
  if (!(info1 & Cr_valid))
    {
      // No decode assist information was provided for the access:
      // "If the instruction is LMSW no additional information is provided."
      Err().printf("LMSW write to CR0 not supported.\n");
      return -1;
    }

  l4_umword_t newval = read_gpr(regs, info1 & Cr_gpr_mask);

  auto old_cr0 = _vmcb->state_save_area.cr0;
  trace().printf("Write to cr0: 0x%llx -> 0x%lx\n", old_cr0, newval);
  // 0x10 => Extension Type; hardcoded to 1 see manual
  _vmcb->state_save_area.cr0 = newval | 0x10;
  mark_dirty(Vmcb_crx);

  if ((newval & Cr0_pg)
      && (old_cr0 & Cr0_pg) == 0
      && (_vmcb->state_save_area.efer & Efer_lme))
    {
      // indicate that long mode is active
      info().printf("Enable long mode\n");
      _vmcb->state_save_area.efer |= Efer_lma;
    }

  if ((newval & Cr0_pg) == 0
      && (old_cr0 & Cr0_pg))
    {
      trace().printf("Disabling paging ...\n");

      if (_vmcb->state_save_area.efer & Efer_lme)
        _vmcb->state_save_area.efer &= ~Efer_lma;
    }

  return Jump_instr;
}

int
Svm_state::handle_xsetbv(l4_vcpu_regs_t *regs)
{
  // TODO: We have to check that the current privilege level is 0, and inject
  // a general protection exception into the guest otherwise!
  if (_vmcb->state_save_area.cpl != 0)
    {
      warn().printf(
        "Ignoring write to extended control register %ld from CPL %d.\n",
        regs->cx, _vmcb->state_save_area.cpl);
      return Jump_instr;
    }

  if (regs->cx == 0)
    {
      l4_uint64_t value = (l4_uint64_t(regs->ax) & 0xFFFFFFFF)
                          | (l4_uint64_t(regs->dx) << 32);
      _vmcb->state_save_area.xcr0 = value;
      trace().printf("Setting xcr0 to 0x%llx\n", value);
      return Jump_instr;
    }

  info().printf("Writing unknown extended control register %ld\n", regs->cx);
  return -L4_EINVAL;
}

int
Svm_state::handle_hardware_exception(Event_recorder *ev_rec, unsigned num)
{
  Err err;

  // Besides #DB and #AC all hardware exceptions are reflected to the guest.
  // The print statements serve as (paranoid) debug help in case the reflection
  // does not happen.
  switch (num)
  {
    case 0: err.printf("Hardware exception: Divide error\n"); break;

    case 1: // #DB
      {
        ev_rec->make_add_event<Event_exc>(Event_prio::Exception, num);
        // #DB exceptions are either of fault type or of trap type. We reflect
        // both to the guest, without changing state, thus don't change the IP.
        return Retry;
      }

    case 3: err.printf("Hardware exception: Breakpoint\n"); break;
    case 4: err.printf("Hardware exception: Overflow\n"); break;
    case 5: err.printf("Hardware exception: Bound range\n"); break;
    case 6: err.printf("Hardware exception: Invalid opcode\n"); break;
    case 7: err.printf("Hardware exception: Device not available\n"); break;
    case 8: err.printf("Hardware exception: Double fault\n"); break;
    case 10: err.printf("Hardware exception: Invalid TSS\n"); break;
    case 11: err.printf("Hardware exception: Segment not present\n"); break;
    case 12: err.printf("Hardware exception: Stack-segment fault\n"); break;
    case 13: err.printf("Hardware exception: General protection\n"); break;
    case 14: err.printf("Hardware exception: Page fault\n"); break;
    case 16: err.printf("Hardware exception: FPU error\n"); break;

    case 17: // #AC
      {
        l4_uint64_t err_code = exit_info1();
        ev_rec->make_add_event<Event_exc>(Event_prio::Exception, num, err_code);
        return Retry;
      }
    case 18: err.printf("Hardware exception: Machine check\n"); break;
    case 19: err.printf("Hardware exception: SIMD error\n"); break;
    default: err.printf("Hardware exception: Unknown exception\n"); break;
  }

  return -L4_EINVAL;
}

l4_umword_t
Svm_state::read_gpr(l4_vcpu_regs_t *regs, unsigned reg) const
{
  switch(reg)
    {
    case 0: return regs->ax;
    case 1: return regs->cx;
    case 2: return regs->dx;
    case 3: return regs->bx;
    case 4: return _vmcb->state_save_area.rsp;
    case 5: return regs->bp;
    case 6: return regs->si;
    case 7: return regs->di;
    case 8: return regs->r8;
    case 9: return regs->r9;
    case 10: return regs->r10;
    case 11: return regs->r11;
    case 12: return regs->r12;
    case 13: return regs->r13;
    case 14: return regs->r14;
    case 15: return regs->r15;
    default: L4Re::throw_error(-L4_EINVAL, "Invalid register num.");
    }
}

const char *
Svm_state::str_exit_code(Exit exit)
{
  l4_uint32_t code = static_cast<l4_uint32_t>(exit);

  if (/* code >= 0x00 && */ code <= 0x0f)
    return "Read of CR 0-15";

  if (code >= 0x10 && code <= 0x1f)
    return "Write of CR 0-15";

  if (code >= 0x20 && code <= 0x2f)
    return "Read of DR 0-15";

  if (code >= 0x30 && code <= 0x3f)
    return "Write of DR 0-15";

  if (code >= 0x40 && code <= 0x5f)
    return "Exception vector 0-31";

  if (code >= 0x90 && code <= 0x9f)
    return "Write of CR 0-15 (trap)";

  switch (code)
  {
    case 0x60: return "Physical INTR (maskable interrupt)";
    case 0x61: return "Physical NMI";
    case 0x62: return "Physical SMI";
    case 0x63: return "Physical INIT";
    case 0x64: return "Virtual INTR";
    case 0x65: return "Write of CR0 that changed any bits other than CR0.TS or CR0.MP";
    case 0x66: return "Read of IDTR";
    case 0x67: return "Read of GDTR";
    case 0x68: return "Read of LDTR";
    case 0x69: return "Read of TR";
    case 0x6A: return "Write of IDTR";
    case 0x6B: return "Write of GDTR";
    case 0x6C: return "Write of LDTR";
    case 0x6D: return "Write of TR";
    case 0x6E: return "RDTSC instruction";
    case 0x6F: return "RDPMC instruction";
    case 0x70: return "PUSHF instruction";
    case 0x71: return "POPF instruction";
    case 0x72: return "CPUID instruction";
    case 0x73: return "RSM instruction";
    case 0x74: return "IRET instruction";
    case 0x75: return "Software interrupt (INTn instructions)";
    case 0x76: return "INVD instruction";
    case 0x77: return "PAUSE instruction";
    case 0x78: return "HLT instruction";
    case 0x79: return "INVLPG instructions";
    case 0x7A: return "INVLPGA instruction";
    case 0x7B: return "IN or OUT accessing protected port";
    case 0x7C: return "RDMSR or WRMSR access to protected MSR";
    case 0x7D: return "Task switch";
    case 0x7E: return "FP error freeze";
    case 0x7F: return "Shutdown";
    case 0x80: return "VMRUN instruction";
    case 0x81: return "VMMCALL instruction";
    case 0x82: return "VMLOAD instruction";
    case 0x83: return "VMSAVE instruction";
    case 0x84: return "STGI instruction";
    case 0x85: return "CLGI instruction";
    case 0x86: return "SKINIT instruction";
    case 0x87: return "RDTSCP instruction";
    case 0x88: return "ICEBP instruction";
    case 0x89: return "WBINVD or WBNOINVD instruction";
    case 0x8A: return "MONITOR or MONITORX instruction";
    case 0x8B: return "MWAIT or MWAITX instruction";
    case 0x8C: return "MWAIT or MWAITX instruction, if monitor hardware is armed.";
    case 0x8E: return "RDPRU instruction";
    case 0x8D: return "XSETBV instruction";
    case 0x8F: return "Write of EFER MSR";
    case 0xA3: return "MCOMMIT instruction";
    case 0x400: return "Nested paging host-level page fault";
    case 0x401: return "AVIC Virtual IPI delivery not completed";
    case 0x402: return "AVIC Access to unaccelerated vAPIC register";
    case 0x403: return "VMGEXIT instruction";
    case -1U: return "Invalid guest state in VMCB";
    default: return nullptr;
  }
}

void
Svm_state::dump(l4_vcpu_regs_t const *regs) const
{
  warn().printf("Registers:\n");
  warn().printf("r15=0x%lx\n", regs->r15);     /**< r15 register */
  warn().printf("r14=0x%lx\n", regs->r14);     /**< r14 register */
  warn().printf("r13=0x%lx\n", regs->r13);     /**< r13 register */
  warn().printf("r12=0x%lx\n", regs->r12);     /**< r12 register */
  warn().printf("r11=0x%lx\n", regs->r11);     /**< r11 register */
  warn().printf("r10=0x%lx\n", regs->r10);     /**< r10 register */
  warn().printf("r9=0x%lx\n", regs->r9);      /**< r9 register */
  warn().printf("r8=0x%lx\n", regs->r8);      /**< r8 register */

  warn().printf("di=0x%lx\n", regs->di);      /**< rdi register */
  warn().printf("si=0x%lx\n", regs->si);      /**< rsi register */
  warn().printf("bp=0x%lx\n", regs->bp);      /**< rbp register */
  warn().printf("pfa=0x%lx\n", regs->pfa);     /**< page fault address */
  warn().printf("bx=0x%lx\n", regs->bx);      /**< rbx register */
  warn().printf("dx=0x%lx\n", regs->dx);      /**< rdx register */
  warn().printf("cx=0x%lx\n", regs->cx);      /**< rcx register */
  warn().printf("ax=0x%lx\n", regs->ax);      /**< rax register */

  warn().printf("trapno=0x%lx\n", regs->trapno);  /**< trap number */
  warn().printf("err=0x%lx\n", regs->err);     /**< error code */

  warn().printf("ip=0x%lx\n", regs->ip);      /**< instruction pointer */
  warn().printf("cs=0x%lx\n", regs->cs);      /**< dummy \internal */
  warn().printf("flags=0x%lx\n", regs->flags);   /**< eflags */
  warn().printf("sp=0x%lx\n", regs->sp);      /**< stack pointer */
  warn().printf("ss=0x%lx\n", regs->ss);
  warn().printf("fs_base=0x%lx\n", regs->fs_base);
  warn().printf("gs_base=0x%lx\n", regs->gs_base);
  warn().printf("ds=0x%x\n", regs->ds);
  warn().printf("es=0x%x\n", regs->es);
  warn().printf("fs=0x%x\n", regs->fs);
  warn().printf("gs=0x%x\n", regs->gs);


  warn().printf("Control area:\n");
  warn().printf("intercept_rd_crX=0x%x\n", _vmcb->control_area.intercept_rd_crX);
  warn().printf("intercept_wr_crX=0x%x\n", _vmcb->control_area.intercept_wr_crX);

  warn().printf("intercept_rd_drX=0x%x\n", _vmcb->control_area.intercept_rd_drX);
  warn().printf("intercept_wr_drX=0x%x\n", _vmcb->control_area.intercept_wr_drX);

  warn().printf("intercept_exceptions=0x%x\n", _vmcb->control_area.intercept_exceptions);

  warn().printf("intercept_instruction0=0x%x\n", _vmcb->control_area.intercept_instruction0);
  warn().printf("intercept_instruction1=0x%x\n", _vmcb->control_area.intercept_instruction1);


  warn().printf("pause_filter_threshold=0x%x\n", _vmcb->control_area.pause_filter_threshold);
  warn().printf("pause_filter_count=0x%x\n", _vmcb->control_area.pause_filter_count);

  warn().printf("iopm_base_pa=0x%llx\n", _vmcb->control_area.iopm_base_pa);
  warn().printf("msrpm_base_pa=0x%llx\n", _vmcb->control_area.msrpm_base_pa);
  warn().printf("tsc_offset=0x%llx\n", _vmcb->control_area.tsc_offset);
  warn().printf("guest_asid_tlb_ctl=0x%llx\n", _vmcb->control_area.guest_asid_tlb_ctl);
  warn().printf("interrupt_ctl=0x%llx\n", _vmcb->control_area.interrupt_ctl);
  warn().printf("interrupt_shadow=0x%llx\n", _vmcb->control_area.interrupt_shadow);
  warn().printf("exitcode=0x%llx\n", _vmcb->control_area.exitcode);
  warn().printf("exitinfo1=0x%llx\n", _vmcb->control_area.exitinfo1);
  warn().printf("exitinfo2=0x%llx\n", _vmcb->control_area.exitinfo2);
  warn().printf("exitintinfo=0x%llx\n", _vmcb->control_area.exitintinfo);
  warn().printf("np_enable=0x%llx\n", _vmcb->control_area.np_enable);


  warn().printf("eventinj=0x%llx\n", _vmcb->control_area.eventinj);
  warn().printf("n_cr3=0x%llx\n", _vmcb->control_area.n_cr3);
  warn().printf("lbr_virtualization_enable=0x%llx\n", _vmcb->control_area.lbr_virtualization_enable);
  warn().printf("clean_bits=0x%llx\n", _vmcb->control_area.clean_bits);
  warn().printf("n_rip=0x%llx\n", _vmcb->control_area.n_rip);


  warn().printf("State save area:\n");
  warn().printf("es: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.es.selector,
                _vmcb->state_save_area.es.attrib,
                _vmcb->state_save_area.es.limit,
                _vmcb->state_save_area.es.base);
  warn().printf("cs: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.cs.selector,
                _vmcb->state_save_area.cs.attrib,
                _vmcb->state_save_area.cs.limit,
                _vmcb->state_save_area.cs.base);
  warn().printf("ss: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.ss.selector,
                _vmcb->state_save_area.ss.attrib,
                _vmcb->state_save_area.ss.limit,
                _vmcb->state_save_area.ss.base);
  warn().printf("ds: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.ds.selector,
                _vmcb->state_save_area.ds.attrib,
                _vmcb->state_save_area.ds.limit,
                _vmcb->state_save_area.ds.base);
  warn().printf("fs: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.fs.selector,
                _vmcb->state_save_area.fs.attrib,
                _vmcb->state_save_area.fs.limit,
                _vmcb->state_save_area.fs.base);
  warn().printf("gs: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.gs.selector,
                _vmcb->state_save_area.gs.attrib,
                _vmcb->state_save_area.gs.limit,
                _vmcb->state_save_area.gs.base);
  warn().printf("gdtr: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.gdtr.selector,
                _vmcb->state_save_area.gdtr.attrib,
                _vmcb->state_save_area.gdtr.limit,
                _vmcb->state_save_area.gdtr.base);
  warn().printf("ldtr: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.ldtr.selector,
                _vmcb->state_save_area.ldtr.attrib,
                _vmcb->state_save_area.ldtr.limit,
                _vmcb->state_save_area.ldtr.base);
  warn().printf("idtr: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.idtr.selector,
                _vmcb->state_save_area.idtr.attrib,
                _vmcb->state_save_area.idtr.limit,
                _vmcb->state_save_area.idtr.base);
  warn().printf("tr: selector=0x%x, attrib=0x%x, limit=0x%x, base=0x%llx)\n",
                _vmcb->state_save_area.tr.selector,
                _vmcb->state_save_area.tr.attrib,
                _vmcb->state_save_area.tr.limit,
                _vmcb->state_save_area.tr.base);


  warn().printf("cpl=0x%x\n", _vmcb->state_save_area.cpl);


  warn().printf("efer=0x%llx\n", _vmcb->state_save_area.efer);


  warn().printf("cr4=0x%llx\n", _vmcb->state_save_area.cr4);
  warn().printf("cr3=0x%llx\n", _vmcb->state_save_area.cr3);
  warn().printf("cr0=0x%llx\n", _vmcb->state_save_area.cr0);
  warn().printf("dr7=0x%llx\n", _vmcb->state_save_area.dr7);
  warn().printf("dr6=0x%llx\n", _vmcb->state_save_area.dr6);
  warn().printf("rflags=0x%llx\n", _vmcb->state_save_area.rflags);
  warn().printf("rip=0x%llx\n", _vmcb->state_save_area.rip);


  warn().printf("rsp=0x%llx\n", _vmcb->state_save_area.rsp);


  warn().printf("rax=0x%llx\n", _vmcb->state_save_area.rax);
  warn().printf("star=0x%llx\n", _vmcb->state_save_area.star);
  warn().printf("lstar=0x%llx\n", _vmcb->state_save_area.lstar);
  warn().printf("cstar=0x%llx\n", _vmcb->state_save_area.cstar);
  warn().printf("sfmask=0x%llx\n", _vmcb->state_save_area.sfmask);
  warn().printf("kernelgsbase=0x%llx\n", _vmcb->state_save_area.kernelgsbase);
  warn().printf("sysenter_cs=0x%llx\n", _vmcb->state_save_area.sysenter_cs);
  warn().printf("sysenter_esp=0x%llx\n", _vmcb->state_save_area.sysenter_esp);
  warn().printf("sysenter_eip=0x%llx\n", _vmcb->state_save_area.sysenter_eip);
  warn().printf("cr2=0x%llx\n", _vmcb->state_save_area.cr2);


  warn().printf("g_pat=0x%llx\n", _vmcb->state_save_area.g_pat);
  warn().printf("dbgctl=0x%llx\n", _vmcb->state_save_area.dbgctl);
  warn().printf("br_from=0x%llx\n", _vmcb->state_save_area.br_from);
  warn().printf("br_to=0x%llx\n", _vmcb->state_save_area.br_to);
  warn().printf("lastexcpfrom=0x%llx\n", _vmcb->state_save_area.lastexcpfrom);
  warn().printf("last_excpto=0x%llx\n", _vmcb->state_save_area.last_excpto);

  // this field is _NOT_ part of the official VMCB specification
  // a (userlevel) VMM needs this for proper FPU state virtualization
  warn().printf("xcr0=0x%llx\n", _vmcb->state_save_area.xcr0);
}

} //namespace Vmm
