/*
 * Copyright (C) 2019, 2023 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>

#include "vcpu_ptr.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Cpu_dev_cmd_handler {};

template<typename T>
class Cpu_dev_cmd_handler<true, T> : public Cmd
{
public:
  char const *help() const override
  { return "CPU state"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'cpu <i> regs': dump CPU registers\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  { compl_req->complete(f, "regs"); }

  void exec(FILE *f, Arglist *args) override
  {
    if (*args == "regs")
      show_regs(f);
    else
      argument_error("Invalid subcommand");
  }

  void show_regs(FILE *f) const
  {
    auto v = get_vcpu();

    fprintf(f, "EPC=%08lx SP=%08lx\n",
            v->r.ip, v->r.sp);
    fprintf(f, "Status=%08lx  Cause=%08lx\n",
            v->r.status, v->r.cause);
    fprintf(f, "ULR=%08lx  Hi=%08lx Lo=%08lx\n",
            v->r.ulr, v->r.hi, v->r.lo);
    fprintf(f, "at/ 1=%08lx v0/ 2=%08lx v1/ 3=%08lx\n",
            v->r.r[1], v->r.r[2], v->r.r[3]);
    fprintf(f, "a0/ 4=%08lx a1/ 5=%08lx a1/ 6=%08lx a4/ 7=%08lx\n",
            v->r.r[4], v->r.r[5], v->r.r[6], v->r.r[7]);
    fprintf(f, "t0/ 8=%08lx t1/ 9=%08lx t2/10=%08lx t3/11=%08lx\n",
            v->r.r[8], v->r.r[9], v->r.r[10], v->r.r[11]);
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

    fprintf(f, "\nGuestCtl0= %08lx  Guestctl0_ext= %08lx\n",
            s->guest_ctl_0, s->guest_ctl_0_ext);
    fprintf(f, "GuestCtl1= %08lx  Guestctl2    = %08lx\n",
            s->guest_ctl_1, s->guest_ctl_2);
    fprintf(f, "\nGuest CP0:\n");
    fprintf(f, "Status   = %08lx  Cause    = %08lx\n",
            s->g_status, s->g_cause);
    fprintf(f, "Index    = %08lx  EBase    = %08lx\n",
            s->g_index, s->g_ebase);
    fprintf(f, "EntryLo0 = %08lx  EntryLo1 = %08lx\n",
            s->g_entry_lo[0], s->g_entry_lo[1]);
    fprintf(f, "Context  = %08lx  EntryHi  = %08lx\n",
            s->g_context, s->g_entry_hi);
    fprintf(f, "PageMask = %08lx  PageGrain= %08lx\n",
            s->g_page_mask, s->g_page_grain);
    fprintf(f, "ULR      = %08lx  Wired    = %08lx\n",
            s->g_ulr, s->g_wired);
    fprintf(f, "SegCtl0  = %08lx  SegCtl1  = %08lx\n",
            s->g_seg_ctl[0], s->g_seg_ctl[1]);
    fprintf(f, "SegCtl2  = %08lx  HWRena   = %08lx\n",
            s->g_seg_ctl[2], s->g_hwrena);
    fprintf(f, "PWBase   = %08lx  PWField  = %08lx\n",
            s->g_pw_base, s->g_pw_field);
    fprintf(f, "PWSize   = %08lx  PWCtl    = %08lx\n",
            s->g_pw_size, s->g_pw_ctl);
    fprintf(f, "BadVAddr = %08lx  BadInstr = %08lx\n",
            s->g_bad_v_addr, s->g_bad_instr);
    fprintf(f, "BadInstrP= %08lx  Compare  = %08lx\n",
            s->g_bad_instr_p, s->g_compare);
    fprintf(f, "IntCtl   = %08lx  EPC      = %08lx\n",
            s->g_intctl, s->g_epc);
    fprintf(f, "Config0  = %08lx  Config1  = %08lx\n",
            s->g_cfg[0], s->g_cfg[1]);
    fprintf(f, "Config2  = %08lx  Config3  = %08lx\n",
            s->g_cfg[2], s->g_cfg[3]);
    fprintf(f, "Config4  = %08lx  Config5  = %08lx\n",
            s->g_cfg[4], s->g_cfg[5]);
  }

private:
  Vmm::Vcpu_ptr get_vcpu() const
  { return static_cast<T const *>(this)->vcpu(); }
};

}
