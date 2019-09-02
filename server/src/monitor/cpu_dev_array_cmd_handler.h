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
#include <string>
#include <vector>

#include "cpu_dev.h"
#include "monitor.h"
#include "monitor_util.h"

namespace Monitor {

template<bool, typename T>
class Cpu_dev_array_cmd_handler {};

template<typename T>
class Cpu_dev_array_cmd_handler<true, T> : public Cmd
{
  enum { Max_cpus = Vmm::Cpu_dev::Max_cpus };

public:
  Cpu_dev_array_cmd_handler()
  { register_toplevel("cpu"); }

  char const *help() const override
  { return "CPU state"; }

  void complete(FILE *f, char const *args) const override
  {
    simple_complete(f, args, {"list"});

    size_t arglen = strlen(args);

    for (int i = 0; i < Max_cpus; ++i)
      {
        if (!cpu_valid(i))
          continue;

        std::string s(std::to_string(i));
        if (arglen < s.size())
          {
            if (strncmp(args, s.c_str(), arglen) == 0)
              fprintf(f, "%s\n", s.c_str());
          }
        else if (arglen > s.size())
          {
            if (strncmp(args, s.c_str(), s.size()) == 0)
              {
                char const *subargs = args + s.size() + 1;
                while (*subargs && *subargs == ' ')
                  ++subargs;

                get_cpu(i)->complete(f, subargs);
              }
          }
      }
  }

  void exec(FILE *f, char const *args) override
  {
    auto argv = split_params(args, 2);

    if (argv.empty())
      {
        print_help(f);
        return;
      }

    if (argv.size() == 1 && argv[0] == "list")
      list_cpus(f);
    else
      exec_subcmd(f, argv);
  }

private:
  void print_help(FILE *f) const
  {
    fprintf(f, "%s\n"
               "* 'cpu list': list available CPUs\n"
               "* 'cpu <i> <subcmd>': execute <subcmd> for CPU <i>\n",
               help());
  }

  bool cpu_valid(unsigned i) const
  { return i < Max_cpus && get_cpu(i); }

  void list_cpus(FILE *f) const
  {
    fprintf(f, "Available CPUs:\n");
    for (int i = 0; i < Max_cpus; ++i)
      {
        if (cpu_valid(i))
          fprintf(f, "CPU %d\n", i);
      }
  }

  void exec_subcmd(FILE *f, std::vector<std::string> const &argv)
  {
    unsigned i = 0;
    if (!stou(argv[0].c_str(), &i))
      {
        print_help(f);
        return;
      }

    if (!cpu_valid(i))
      {
        fprintf(f, "Invalid CPU\n");
      }
    else
      {
        char const *subargs = argv.size() == 2 ? argv[1].c_str() : "";
        get_cpu(i)->exec(f, subargs);
      }
  }

  Vmm::Cpu_dev *get_cpu(unsigned i)
  { return static_cast<T *>(this)->_cpus[i].get(); }

  Vmm::Cpu_dev const *get_cpu(unsigned i) const
  { return static_cast<T const *>(this)->_cpus[i].get(); }
};

}
