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

#include "monitor.h"

namespace Monitor {

template<bool, typename T>
class Virtio_input_power_cmd_handler {};

template<typename T>
class Virtio_input_power_cmd_handler<true, T> : public Cmd
{
public:
  Virtio_input_power_cmd_handler()
  { register_toplevel("sysrq"); }

  char const *help() const override
  { return "Send system request"; }

  void exec(FILE *f, char const *args) override
  {
    if (strlen(args) != 1)
      {
        fprintf(f, "Key expected (try 'h' for help).\n");
        return;
      }

    if (!virtio_input_power()->inject_command(args[0]))
      fprintf(f, "failed to inject event\n");
  }

private:
  T * virtio_input_power()
  { return static_cast<T *>(this); }
};

}
