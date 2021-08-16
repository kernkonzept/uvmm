/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <cstdio>
#include <cstring>

#include <l4/util/l4_macros.h>

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
    fprintf(f, "pc     = " l4_addr_fmt "\n", v->r.pc);
    fprintf(f, "sp     = " l4_addr_fmt "\n", v->r.sp);
    fprintf(f, "ra     = " l4_addr_fmt "\n", v->r.ra);
    fprintf(f, "status = " l4_addr_fmt "\n", v->r.status);
    fprintf(f, "cause  = " l4_addr_fmt "\n", v->r.cause);
    fprintf(f, "pfa    = " l4_addr_fmt "\n", v->r.pfa);
    fprintf(f, "\n");
    fprintf(f, "gp = " l4_addr_fmt "  tp = " l4_addr_fmt "\n",
            v->r.gp, v->r.tp);
    fprintf(f, "t0 = " l4_addr_fmt "  t1 = " l4_addr_fmt
             "  t2 = " l4_addr_fmt " \n", v->r.t0, v->r.t1, v->r.t2);
    fprintf(f, "t3 = " l4_addr_fmt "  t4 = " l4_addr_fmt
             "  t5 = " l4_addr_fmt "  t6 = " l4_addr_fmt " \n",
            v->r.t3, v->r.t4, v->r.t5, v->r.t6);
    fprintf(f, "s0 = " l4_addr_fmt "  s1 = " l4_addr_fmt
             "  s2 = " l4_addr_fmt "  s3 = " l4_addr_fmt " \n",
            v->r.s0, v->r.s1, v->r.s2, v->r.s3);
    fprintf(f, "s4 = " l4_addr_fmt "  s5 = " l4_addr_fmt
             "  s6 = " l4_addr_fmt "  s7 = " l4_addr_fmt " \n",
            v->r.s4, v->r.s5, v->r.s6, v->r.s7);
    fprintf(f, "s8 = " l4_addr_fmt "  s9 = " l4_addr_fmt
             " s10 = " l4_addr_fmt " s11 = " l4_addr_fmt " \n",
            v->r.s8, v->r.s9, v->r.s10, v->r.s11);
    fprintf(f, "a0 = " l4_addr_fmt "  a1 = " l4_addr_fmt
             "  a2 = " l4_addr_fmt "  a3 = " l4_addr_fmt " \n",
            v->r.a0, v->r.a1, v->r.a2, v->r.a3);
    fprintf(f, "a4 = " l4_addr_fmt "  a5 = " l4_addr_fmt
             "  a6 = " l4_addr_fmt "  a7 = " l4_addr_fmt " \n",
            v->r.a4, v->r.a5, v->r.a6, v->r.a7);
    fprintf(f, "\n");

    auto s = v.vm_state();
    fprintf(f, "hstatus    = " l4_addr_fmt "\n", v->r.hstatus);
    fprintf(f, "htval      = " l4_addr_fmt "\n", s->htval);
    fprintf(f, "htinst     = " l4_addr_fmt "\n", s->htinst);
    fprintf(f, "hedeleg    = " l4_addr_fmt "\n", s->hedeleg);
    fprintf(f, "hideleg    = " l4_addr_fmt "\n", s->hideleg);
    fprintf(f, "hvip       = " l4_addr_fmt "\n", s->hvip);
    fprintf(f, "hip        = " l4_addr_fmt "\n", s->hip);
    fprintf(f, "hie        = " l4_addr_fmt "\n", s->hie);
    fprintf(f, "htimedelta = %016llx\n", s->htimedelta);
    fprintf(f, "\n");
    fprintf(f, "vsepc      = " l4_addr_fmt "\n", s->vsepc);
    fprintf(f, "vsstatus   = " l4_addr_fmt "\n", s->vsstatus);
    fprintf(f, "vscause    = " l4_addr_fmt "\n", s->vscause);
    fprintf(f, "vstval     = " l4_addr_fmt "\n", s->vstval);
    fprintf(f, "vstvec     = " l4_addr_fmt "\n", s->vstvec);
    fprintf(f, "vsscratch  = " l4_addr_fmt "\n", s->vsscratch);
    fprintf(f, "vsatp      = " l4_addr_fmt "\n", s->vsatp);
  }

private:
  Vmm::Vcpu_ptr get_vcpu() const
  { return static_cast<T const *>(this)->vcpu(); }
};

}
