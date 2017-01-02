/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cassert>
#include <utility>

#include "vcpu_array.h"

static const std::pair<l4_umword_t, const char *> MIPS_PROC_IDS[] =
  {{0x0001a700, "mips,m5150"},
   {0x0001a800, "mips,p5600"},
   {0x0001a900, "mips,i6400"},
   {0, nullptr}};

static Dbg warn(Dbg::Cpu, Dbg::Warn, "CPC");
static Dbg info(Dbg::Cpu, Dbg::Info, "CPC");
static Dbg trace(Dbg::Cpu, Dbg::Trace, "CPC");

namespace Vmm
{

void
Vcpu_dev::set_proc_type(char const *compatible)
{
  for (auto *row = MIPS_PROC_IDS; row->second; ++row)
    {
      if (strcmp(row->second, compatible) == 0)
        {
          _vcpu.set_proc_id(row->first);
          return;
        }
    }

  _vcpu.set_proc_id(Default_procid);
}

void
Vcpu_array::show_state_registers(FILE *f)
{
  for (int i = 0; i < Max_cpus; ++i)
    {
      if (!_cpus[i])
        continue;

      // if (i != current_cpu)
      //  interrupt_vcpu(i);

      Cpu v = _cpus[i]->vcpu();
      fprintf(f, "CPU %d\n", i);
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
}

l4_umword_t
Vcpu_array::read(unsigned reg, char, unsigned cpuid)
{
  trace.printf("reading CPC @ 0x%x\n", reg);

  if (reg >= Core_local_base && reg < Core_local_base + Control_block_size)
    return cpc_read_core(reg - Core_local_base, cpuid);

  if (reg >= Core_other_base && reg < Core_other_base + Control_block_size)
    {
      if ((cpuid >= Max_cpus) || !_cpus[cpuid])
        {
          info.printf("read on unknown other core %d. Ignored.\n", cpuid);
          return 0;
        }

      return cpc_read_core(reg - Core_other_base, _cpus[cpuid]->core_other());
    }

  info.printf("reading unknown register @ 0x%x ignored.\n", reg);
  return 0;
}

void
Vcpu_array::write(unsigned reg, char, l4_umword_t value, unsigned cpuid)
{
  trace.printf("writing CPC 0x%lx @ 0x%x\n", value, reg);

  if (reg >= Core_local_base && reg < Core_local_base + Control_block_size)
    cpc_write_core(reg - Core_local_base, value, cpuid);
  else if (reg >= Core_other_base && reg < Core_other_base + Control_block_size)
    {
      if ((cpuid < Max_cpus) && _cpus[cpuid])
        cpc_write_core(reg - Core_other_base, value, _cpus[cpuid]->core_other());
      else
        info.printf("read on unknown other core %d. Ignored.\n", cpuid);
    }
  else
    info.printf("writing unknown register 0x%lx @ 0x%x ignored.\n", value, reg);
}

l4_umword_t
Vcpu_array::cpc_read_core(unsigned reg, unsigned cpuid)
{
  if (cpuid >= Max_cpus || !_cpus[cpuid])
    {
      info.printf("CPC reading from uninitialised core %d ignored.\n", cpuid);
      return 0;
    }

  trace.printf("core %d: reading CPC @ 0x%x\n", cpuid, reg);

  switch (reg)
    {
    case Cpc_cl_stat_conf_reg:
      return _cpus[cpuid]->cpc_status();
    default:
      info.printf("core %d: reading CPC @ 0x%x ignored.\n", cpuid, reg);
    }

  return 0;
}

void
Vcpu_array::cpc_write_core(unsigned reg, l4_umword_t value, unsigned cpuid)
{
  if (cpuid >= Max_cpus || !_cpus[cpuid])
    {
      info.printf("CPC writing to uninitialised core %d ignored.\n", cpuid);
      return;
    }

  trace.printf("core %d: writing CPC 0x%lx @ 0x%x\n", cpuid, value, reg);

  switch (reg)
    {
    case Cpc_cl_cmd_reg:
      {
        unsigned cmd = value & 0x7;
        _cpus[cpuid]->set_last_command(cmd);

        switch (cmd)
          {
          case Cpc_cmd_pwr_down:
            _cpus[cpuid]->stop_vcpu();
            break;
          case Cpc_cmd_pwr_up:
          case Cpc_cmd_reset:
            _cpus[cpuid]->start_vcpu(_bev_base);
            break;
          }
        break;
      }
    default:
      info.printf("core %d: writing 0x%lx @ 0x%x ignored.\n",
                  cpuid, value, reg);
    }
}

void
Vcpu_dev::start_vcpu(l4_addr_t bev_base)
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
  _vcpu.ping();

  // consider it officially done
  // XXX should that be done in reset code?
  set_coherent();
}

void
Vcpu_dev::stop_vcpu()
{
  warn.printf("Stop of vcpu %d requested. NOT IMPLEMENTED.\n",
              _vcpu.get_vcpu_id());
}

} // namespace
