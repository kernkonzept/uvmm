/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>

#include "cpu_dev.h"
#include "monitor.h"
#include "show_state_registers.h"

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

  char const *help() const override { return "CPU registers"; }

  void exec(FILE *f, char const *args) override
  {
    if (strcmp(args, "list") == 0)
      {
        list_all_cpus(f);
      }
    else if (strlen(args) == 0)
      {
        show_all_cpus(f);
      }
    else
      {
        int i;
        if (!stoi(args, &i))
          print_help(f);
        else
          show_one_cpu(i, f);
      }
  }

private:
  static void print_help(FILE *f)
  {
    fprintf(f, "Dump CPU registers:\n"
               "* Use 'cpu list' to list available cpus\n"
               "* Use 'cpu' to dump registers for all cpus at once\n"
               "* Use 'cpu <i>' to registers for a specific cpu\n");
  }

  static bool stoi(char const *str, int *i)
  {
    errno = 0;

    char *endptr;
    long i_l = strtol(str, &endptr, 10);

    bool success = errno == 0
                   && !*endptr
                   && i_l >= 0 && i_l <= INT_MAX;

    if (success)
      *i = i_l;

    return success;
  }

  void list_all_cpus(FILE *f) const
  {
    fprintf(f, "Available CPUs:\n");
    for (int i = 0; i < Max_cpus; ++i)
      {
        if (cpu_valid(i))
          fprintf(f, "CPU %d\n", i);
      }
  }

  void show_all_cpus(FILE *f) const
  {
    bool put_space = false;
    for (int i = 0; i < Max_cpus; ++i)
      {
        if (!cpu_valid(i))
          continue;

        if (put_space)
          fputc('\n', f);
        else
          put_space = true;

        fprintf(f, "CPU %d\n", i);
        show_cpu(i, f);
      }
  }

  void show_one_cpu(int i, FILE *f) const
  {
    if (i >= Max_cpus)
      fprintf(f, "CPU index must be between 0 and %d\n", Max_cpus - 1);
    else if (!cpu_valid(i))
      fprintf(f, "CPU %d not valid\n", i);
    else
      show_cpu(i, f);
  }

  bool cpu_valid(int i) const
  { return !!cpu_dev_array()->_cpus[i]; }

  void show_cpu(int i, FILE *f) const
  { show_state_registers(cpu_dev_array()->_cpus[i].get(), f); }

  T const *cpu_dev_array() const { return static_cast<T const *>(this); }
};

}
