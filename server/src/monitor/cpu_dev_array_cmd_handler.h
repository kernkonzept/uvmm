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

#include "cpu_dev.h"
#include "monitor.h"

namespace Monitor {

template<bool, typename T>
class Cpu_dev_array_cmd_handler {};

template<typename T>
class Cpu_dev_array_cmd_handler<true, T> : public Cmd
{
public:
  Cpu_dev_array_cmd_handler()
  { register_toplevel("cpu"); }

  char const *help() const override { return "CPU registers"; }

  void exec(FILE *f, char const *) override
  {
    for (int i = 0; i < Vmm::Cpu_dev::Max_cpus; ++i)
      {
        if (!cpu_dev_array()->_cpus[i])
          continue;

        fprintf(f, "CPU %d\n", i);
        cpu_dev_array()->_cpus[i]->show_state_registers(f);
      }
  }

private:
  T *cpu_dev_array() { return static_cast<T *>(this); }
};

}
