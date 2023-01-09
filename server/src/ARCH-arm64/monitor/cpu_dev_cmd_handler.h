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

#include <l4/sys/vcpu.h>

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

    for (unsigned i = 0; i < 31; ++i)
      fprintf(f, "x%2d:%16lx%s", i, regs.r[i], (i % 4) == 3 ? "\n" : "  ");

    fprintf(f, "\npc=%lx  sp=%lx  psr=%lx  sctlr=%x\n",
            regs.ip, regs.sp, regs.flags,
            l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR));
  }

private:
  Vmm::Vcpu_ptr get_vcpu() const
  { return static_cast<T const *>(this)->vcpu(); }
};

}
