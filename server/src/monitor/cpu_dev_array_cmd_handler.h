/*
 * Copyright (C) 2019, 2023 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cpu_dev.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Cpu_dev_array_cmd_handler {};

template<typename T>
class Cpu_dev_array_cmd_handler<true, T> : public Cmd
{
public:
  Cpu_dev_array_cmd_handler()
  { register_toplevel("cpu"); }

  char const *help() const override
  { return "CPU state"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'cpu list': list available CPUs\n"
               "* 'cpu <i> <subcmd>': execute <subcmd> for CPU <i>\n"
               "* 'cpu all <subcmd>': execute <subcmd> for all CPUs\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  {
    switch (compl_req->count() + compl_req->trailing_space())
      {
      case 0:
      case 1:
        {
          compl_req->complete(f, "list");

          for (unsigned cpu = 0; cpu < max_cpus(); ++cpu)
            {
              if (!cpu_valid(cpu))
                continue;

              std::string cpu_s(std::to_string(cpu));
              compl_req->complete(f, cpu_s.c_str());
            }
        }
        break;
      default:
        {
          auto cpu_arg = compl_req->pop();
          if (!cpu_arg.check<unsigned>())
            return;

          unsigned cpu = cpu_arg.get<unsigned>();
          if (!cpu_valid(cpu))
            return;

          get_cpu(cpu)->complete(f, compl_req);
        }
      }
  }

  void exec(FILE *f, Arglist *args) override
  {
    if (*args == "list")
      list_cpus(f);
    else if (args->peek() == "all")
      {
        args->pop();

        unsigned i = 0;
        while (cpu_valid(i))
          {
            fprintf(f, "vCPU %u\n", i);
            get_cpu(i)->exec(f, args);
            fprintf(f, "\n");
            ++i;
          }
      }
    else
      exec_subcmd(f, args);
  }

private:
  bool cpu_valid(unsigned i) const
  { return i < max_cpus() && get_cpu(i); }

  void list_cpus(FILE *f) const
  {
    fprintf(f, "Available CPUs:\n");
    for (unsigned i = 0; i < max_cpus(); ++i)
      {
        if (cpu_valid(i))
          fprintf(f, "CPU %u\n", i);
      }
  }

  void exec_subcmd(FILE *f, Arglist *args)
  {
    unsigned cpu = args->pop<unsigned>("Failed to parse VCPU index");

    if (!cpu_valid(cpu))
      argument_error("Invalid CPU");

    get_cpu(cpu)->exec(f, args);
  }

  Vmm::Cpu_dev *get_cpu(unsigned i)
  { return static_cast<T *>(this)->_cpus[i].get(); }

  Vmm::Cpu_dev const *get_cpu(unsigned i) const
  { return static_cast<T const *>(this)->_cpus[i].get(); }

  unsigned max_cpus() const
  { return static_cast<T const *>(this)->_cpus.size(); }
};

}
