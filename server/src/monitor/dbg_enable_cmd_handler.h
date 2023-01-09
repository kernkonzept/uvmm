/*
 * Copyright (C) 2019, 2023 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <memory>

#include "debugger/guest_debugger.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Vmm {
  class Vm;
}

namespace Monitor {

template<bool>
class Dbg_enable_cmd_handler
{
public:
  Dbg_enable_cmd_handler(Vmm::Vm *)
  {}
};

template<>
class Dbg_enable_cmd_handler<true> : public Cmd
{
public:
  Dbg_enable_cmd_handler(Vmm::Vm *vm)
  : _vm(vm)
  { register_toplevel("dbg"); }

  char const *help() const override
  { return "Enable guest debugger"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'dbg on': enable guest debugger interface\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  { compl_req->complete(f, "on"); }

  void exec(FILE *, Arglist *args) override
  {
    if (*args == "on")
      {
        unregister_toplevel();

        _dbg.reset(new Guest_debugger(_vm));
      }
    else
      argument_error("Invalid subcommand");
  }

private:
  Vmm::Vm *_vm;
  std::unique_ptr<Monitor::Guest_debugger> _dbg;
};

} // namespace Monitor
