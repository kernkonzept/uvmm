/*
 * Copyright (C) 2019, 2023 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>

#include <l4/cxx/exceptions>
#include <l4/sys/l4int.h>

#include "monitor/mem_dump.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Dbg_cmd_handler {};

template<typename T>
class Dbg_cmd_handler<true, T> : public Cmd
{
public:
  Dbg_cmd_handler()
  { register_toplevel("dbg"); }

  char const *help() const override
  { return "Guest debugger interface"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'dbg r <vcpu> <addr> [<n> [(b|w|d|q)]]': dump guest memory\n"
               "where: * <vcpu> = VCPU index, this parameter must be specified\n"
               "         if and only if there are multiple VCPUs\n"
               "       * <n> = number of entries to be dumped\n"
               "       * b = byte, w = word (16 bits), d = double word,\n"
               "         q = quad word\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  { compl_req->complete(f, "r"); }

  void exec(FILE *f, Arglist *args) override
  {
    auto subcmd = args->pop();

    unsigned vcpu_idx = 0;
    if (dbg()->vcpu_smp_active())
      vcpu_idx = args->pop<unsigned>("Failed to parse VCPU index");

    if (!dbg()->vcpu_valid(vcpu_idx))
      argument_error("Invalid VCPU index");

    auto vcpu = dbg()->vcpu_ptr(vcpu_idx);

    if (subcmd == "r")
      {
        Mem_dumper mem_dump(args);

        try
          {
            dbg()->dump_memory(f, &mem_dump, vcpu);
          }
        catch (L4::Runtime_error &e)
          {
            fprintf(f, "Page table walk failed: %s", e.extra_str());
          }
      }
    else
      argument_error("Invalid subcommand");
  }

  T *dbg()
  { return static_cast<T *>(this); }
};

}
