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

#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

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
    auto key = args->pop<std::string>("Missing key");

    if (key.size() != 1)
      argument_error("Key expected (try 'h' for help)");

    if (!virtio_input_power()->inject_command(key[0]))
      argument_error("Failed to inject event");
  }

private:
  T * virtio_input_power()
  { return static_cast<T *>(this); }
};

}
