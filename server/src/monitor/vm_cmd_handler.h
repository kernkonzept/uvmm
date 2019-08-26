/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>

#include "monitor.h"
#include "monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Vm_cmd_handler {};

template<typename T>
class Vm_cmd_handler<true, T> : public Cmd
{
public:
  Vm_cmd_handler()
  { register_toplevel("dev"); }

  char const *help() const override
  { return "Device list"; }

  void usage(FILE *f) const
  {
    fprintf(f, "%s\n"
               "* 'dev list': list available devices\n"
               "* 'dev <dev> <args>': execute device specific command\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  {
    compl_req->complete(f, "list");

    for (auto const &d : vm()->_devices)
      compl_req->complete(f, d.path.c_str());
  }

  void exec(FILE *f, Arglist *args) override
  {
    if (*args == "list")
      {
        for (auto const &d : vm()->_devices)
          fprintf(f, " %s\n", d.path.c_str());
      }
    else
      {
        auto subcmd = args->pop();

        bool found_device = false;
        Cmd *monitor = nullptr;

        for (auto const &d : vm()->_devices)
          {
            if (d.path == subcmd)
              {
                found_device = true;
                monitor = dynamic_cast<Cmd *>(d.dev.get());
                break;
              }
          }

        if (found_device)
          {
            if (monitor)
              monitor->exec(f, args);
            else
              argument_error("Not implemented");
          }
        else
          argument_error("Unknown device");
      }
  }

private:
  T const *vm() const
  { return static_cast<T const *>(this); }
};

}
