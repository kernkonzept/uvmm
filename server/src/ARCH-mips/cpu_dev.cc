/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "cpu_dev.h"
#include "guest_entry.h"

static const std::pair<l4_umword_t, const char *> MIPS_PROC_IDS[] =
  {{0x0001a700, "mips,m5150"},
   {0x0001a800, "mips,p5600"},
   {0x0001a900, "mips,i6400"},
   {0x0001b024, "mips,i6500"},
   {0, nullptr}};

static Dbg warn(Dbg::Cpu, Dbg::Warn, "CPU");
static Dbg info(Dbg::Cpu, Dbg::Info, "CPU");
static Dbg trace(Dbg::Cpu, Dbg::Trace, "CPU");

namespace Vmm
{

static l4_umword_t
get_proc_type(char const *compatible)
{
  if (!compatible)
    return Cpu_dev::Default_procid;

  for (auto *row = MIPS_PROC_IDS; row->second; ++row)
    if (strcmp(row->second, compatible) == 0)
      return row->first;

  return Cpu_dev::Default_procid;
}

Cpu_dev::Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *node)
: Generic_cpu_dev(idx, phys_id), _status(0), _core_other(0)
{
  // If a compatible property exists, it may be used to specify
  // the reported CPU type (if supported by architecture). Without
  // compatible property, the default is used.
  char const *compatible = node ? node->get_prop<char>("compatible", nullptr)
                                : nullptr;
  _vcpu.set_proc_id(get_proc_type(compatible));
  _vcpu.alloc_fpu_state();
  _status.seq_state() = Seq_non_coherent;
}

void
Cpu_dev::show_state_registers(FILE *f)
{
  auto v = _vcpu;
  fprintf(f, "EPC=%08lx SP=%08lx\n", v->r.ip, v->r.sp);
  fprintf(f, "Status=%08lx  Cause=%08lx\n", v->r.status, v->r.cause);
  fprintf(f, "ULR=%08lx  Hi=%08lx Lo=%08lx\n", v->r.ulr, v->r.hi, v->r.lo);
  fprintf(f, "at/ 1=%08lx v0/ 2=%08lx v1/ 3=%08lx\n", v->r.r[1], v->r.r[2],
          v->r.r[3]);
  fprintf(f, "a0/ 4=%08lx a1/ 5=%08lx a1/ 6=%08lx a4/ 7=%08lx\n", v->r.r[4],
          v->r.r[5], v->r.r[6], v->r.r[7]);
  fprintf(f, "t0/ 8=%08lx t1/ 9=%08lx t2/10=%08lx t3/11=%08lx\n", v->r.r[8],
          v->r.r[9], v->r.r[10], v->r.r[11]);
  fprintf(f, "t4/12=%08lx t5/13=%08lx t6/14=%08lx t7/15=%08lx\n",
          v->r.r[12], v->r.r[13], v->r.r[14], v->r.r[15]);
  fprintf(f, "s0/16=%08lx s1/17=%08lx s2/18=%08lx s3/19=%08lx\n",
          v->r.r[16], v->r.r[17], v->r.r[18], v->r.r[19]);
  fprintf(f, "s4/20=%08lx s5/21=%08lx s6/22=%08lx s7/23=%08lx\n",
          v->r.r[20], v->r.r[21], v->r.r[22], v->r.r[23]);
  fprintf(f, "t8/24=%08lx t9/25=%08lx k0/26=%08lx k1/27=%08lx\n",
          v->r.r[24], v->r.r[25], v->r.r[26], v->r.r[27]);
  fprintf(f, "gp/28=%08lx sp/29=%08lx s8/30=%08lx ra/31=%08lx\n",
          v->r.r[28], v->r.r[29], v->r.r[30], v->r.r[31]);

  auto *s = v.state();
  s->update_state(~0UL);
  fprintf(f, "\nGuestCtl0= %08lx  Guestctl0_ext= %08lx\n", s->guest_ctl_0,
          s->guest_ctl_0_ext);
  fprintf(f, "GuestCtl1= %08lx  Guestctl2    = %08lx\n", s->guest_ctl_1,
          s->guest_ctl_2);
  fprintf(f, "\nGuest CP0:\n");

  fprintf(f, "Status   = %08lx  Cause    = %08lx\n", s->g_status,
          s->g_cause);
  fprintf(f, "Index    = %08lx  EBase    = %08lx\n", s->g_index, s->g_ebase);
  fprintf(f, "EntryLo0 = %08lx  EntryLo1 = %08lx\n", s->g_entry_lo[0],
          s->g_entry_lo[1]);
  fprintf(f, "Context  = %08lx  EntryHi  = %08lx\n", s->g_context,
          s->g_entry_hi);
  fprintf(f, "PageMask = %08lx  PageGrain= %08lx\n", s->g_page_mask,
          s->g_page_grain);
  fprintf(f, "ULR      = %08lx  Wired    = %08lx\n", s->g_ulr, s->g_wired);
  fprintf(f, "SegCtl0  = %08lx  SegCtl1  = %08lx\n", s->g_seg_ctl[0],
          s->g_seg_ctl[1]);
  fprintf(f, "SegCtl2  = %08lx  HWRena   = %08lx\n", s->g_seg_ctl[2],
          s->g_hwrena);
  fprintf(f, "PWBase   = %08lx  PWField  = %08lx\n", s->g_pw_base,
          s->g_pw_field);
  fprintf(f, "PWSize   = %08lx  PWCtl    = %08lx\n", s->g_pw_size,
          s->g_pw_ctl);
  fprintf(f, "BadVAddr = %08lx  BadInstr = %08lx\n", s->g_bad_v_addr,
          s->g_bad_instr);
  fprintf(f, "BadInstrP= %08lx  Compare  = %08lx\n", s->g_bad_instr_p,
          s->g_compare);
  fprintf(f, "IntCtl   = %08lx  EPC      = %08lx\n", s->g_intctl, s->g_epc);
  fprintf(f, "Config0  = %08lx  Config1  = %08lx\n", s->g_cfg[0],
          s->g_cfg[1]);
  fprintf(f, "Config2  = %08lx  Config3  = %08lx\n", s->g_cfg[2],
          s->g_cfg[3]);
  fprintf(f, "Config4  = %08lx  Config5  = %08lx\n", s->g_cfg[4],
          s->g_cfg[5]);
}

void
Cpu_dev::reset()
{
  l4_umword_t sp;
  asm ("move %0, $sp" : "=r" (sp));

  _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED
                       | L4_VCPU_F_USER_MODE
                       | L4_VCPU_F_IRQ
                       | L4_VCPU_F_PAGE_FAULTS
                       | L4_VCPU_F_EXCEPTIONS;
  _vcpu->entry_ip = (l4_umword_t)&c_vcpu_entry;
  _vcpu->entry_sp = sp & ~0xfUL;
  _vcpu->r.status |= 8;

  auto *s = _vcpu.state();
  // disable trapping of CF1&2, CG and GT, enable ctl2
  s->guest_ctl_0 |= 0x3000083;
  s->guest_ctl_0_ext |= 0x10; // CGI
  l4_umword_t cca = s->g_cfg[0] & 7UL;
  s->g_seg_ctl[0] = 0x00200010;
  s->g_seg_ctl[1] = 0x00000002 | (cca << 16);
  s->g_seg_ctl[2] = 0x04300030 | (cca << 16) | cca;
  s->g_ebase = (s->g_ebase & ~0x3ffUL) | _vcpu.get_vcpu_id();
  s->set_modified(L4_VM_MOD_GUEST_CTL_0
                  | L4_VM_MOD_GUEST_CTL_0_EXT
                  | L4_VM_MOD_CFG
                  | L4_VM_MOD_EBASE
                  | L4_VM_MOD_XLAT);

  Dbg(Dbg::Core, Dbg::Info)
    .printf("Starting vcpu %d @ 0x%lx (handler @ %lx with stack @ %lx)\n",
            _vcpu.get_vcpu_id(), _vcpu->r.ip, _vcpu->entry_ip, _vcpu->entry_sp);

  L4::Cap<L4::Thread> myself;
  auto e = l4_error(myself->vcpu_resume_commit(myself->vcpu_resume_start()));

  Err().printf("VMM exited with %ld\n", e);
}

void
Cpu_dev::start_vcpu(l4_addr_t bev_base)
{
  info.printf("Start of vcpu %d requested.\n", _vcpu.get_vcpu_id());

  // setup vcpu state
  if (_reset_base & 1)
    {
      _vcpu->r.ip = bev_base;
      trace.printf("Using BEV reset base 0x%lx\n", bev_base);
    }
  else
    {
      _vcpu->r.ip = _reset_base & Cm_loc_reset_base_addr_mask;
      trace.printf("Using Core reset base 0x%lx\n", _reset_base);
    }

  _vcpu.state()->g_status |= (1 << 2) | (1 << 22); // ERL, BEV

  reschedule();

  // consider it officially done
  // XXX should that be done in reset code?
  set_coherent();
}

void
Cpu_dev::stop_vcpu()
{
  warn.printf("Stop of vcpu %d requested. NOT IMPLEMENTED.\n",
              _vcpu.get_vcpu_id());
}

} // namespace
