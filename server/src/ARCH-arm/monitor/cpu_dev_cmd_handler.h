/*
 * Copyright (C) 2019, 2021, 2023 Kernkonzept GmbH.
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
    auto vcpu = get_vcpu();
    auto regs = vcpu->r;

    fprintf(f, "pc=%08lx lr=%08lx sp=%08lx flags=%08lx\n",
            regs.ip, vcpu.get_lr(), vcpu.get_sp(), regs.flags);
    fprintf(f, " r0=%08lx  r1=%08lx  r2=%08lx  r3=%08lx\n",
            regs.r[0], regs.r[1], regs.r[2], regs.r[3]);
    fprintf(f, " r4=%08lx  r5=%08lx  r6=%08lx  r7=%08lx\n",
            regs.r[4], regs.r[5], regs.r[6], regs.r[7]);
    fprintf(f, " r8=%08lx  r9=%08lx r10=%08lx r11=%08lx\n",
            vcpu.get_gpr(8), vcpu.get_gpr(9), vcpu.get_gpr(10),
            vcpu.get_gpr(11));
    fprintf(f, "r12=%08lx\n", vcpu.get_gpr(12));
  }

private:
  Vmm::Vcpu_ptr get_vcpu() const
  { return static_cast<T const *>(this)->vcpu(); }
};

}
