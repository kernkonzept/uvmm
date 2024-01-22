/*
 * Copyright (C) 2019-2020, 2023 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include <l4/sys/l4int.h>

#include "mem_dump.h"
#include "mem_types.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Vm_ram_cmd_handler {};

template<typename T>
class Vm_ram_cmd_handler<true, T> : public Cmd
{
public:
  Vm_ram_cmd_handler()
  { register_toplevel("ram"); }

  char const *help() const override
  { return "RAM dataspaces"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'ram ds': list RAM dataspaces\n"
               "* 'ram dump <addr> [<n> [(b|w|d|q)]]': dump RAM region\n"
               "where: * b = byte, w = word (16 bits), d = double word, q = quad word\n"
               "       * <n> = number of entries to be dumped\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  { compl_req->complete(f, {"ds", "dump"}); }

  void exec(FILE *f, Arglist *args) override
  {
    auto subcmd = args->pop();

    if (subcmd == "ds")
      show_dataspaces(f);
    else if (subcmd == "dump")
      dump_memory(f, args);
    else
      argument_error("Invalid subcommand");
  }

private:
  void show_dataspaces(FILE *f) const
  {
    fprintf(f, "Dataspace  Guest area             Size        Local address  Phys?\n");
    for (auto const &r : vm_ram()->_regions)
      fprintf(f, "%9lu  0x%08llx-0x%08llx  0x%08llx  0x%08llx     %s\n",
              r->dataspace().cap() >> L4_CAP_SHIFT,
              static_cast<l4_uint64_t>(r->vm_start().get()),
              static_cast<l4_uint64_t>(r->vm_start().get() + r->size()),
              static_cast<l4_uint64_t>(r->size()),
              static_cast<l4_uint64_t>(r->local_start()),
              r->has_phys_addr() ? "Y" : "N");
  }

  bool dump_memory(FILE *f, Arglist *args) const
  {
    Mem_dumper mem_dumper(args);

    Vmm::Guest_addr ga(mem_dumper.addr_start());

    auto const r = vm_ram()->find_region(ga, 0);
    if (!r)
      argument_error( "Invalid RAM region");

    l4_addr_t addr_hvirt = reinterpret_cast<l4_addr_t>(r->guest2host(ga));
    l4_size_t max_size = r->vm_start().get() - ga.get() + r->size();

    mem_dumper.dump(f, addr_hvirt, max_size);

    return true;
  }

  T const *vm_ram() const
  { return static_cast<T const *>(this); }
};

}
