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
#include "monitor_args.h"

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

  void exec(FILE *, Arglist *args) override
  {
    char key = args->pop<char>("Key expected (try 'h' for help)");

    if (!virtio_input_power()->inject_command(key))
      argument_error("Failed to inject event");
  }

private:
  T * virtio_input_power()
  { return static_cast<T *>(this); }
};

}
