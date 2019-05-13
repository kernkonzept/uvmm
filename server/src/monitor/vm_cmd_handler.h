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

namespace Monitor {

template<bool, typename T>
class Vm_cmd_handler {};

template<typename T>
class Vm_cmd_handler<true, T> : public Cmd
{
public:
  Vm_cmd_handler()
  { register_toplevel("dev"); }

  char const *help() const override { return "Device list"; }

  void complete(FILE *f, char const *args) const override
  {
    if (strncmp(args, "list", strlen(args)) == 0)
      fprintf(f, "list\n");

    for (auto const &d : vm()->_devices)
      {
        if (strncmp(args, d.path.c_str(), strlen(args)) == 0)
          fprintf(f, "%s\n", d.path.c_str());
      }
  }

  void exec(FILE *f, char const *cmd) override
  {
    if (strlen(cmd) == 0)
      {
        fprintf(f, "Use 'dev list' to show available devices\n");
      }
    else if (strcmp(cmd, "list") == 0)
      {
        for (auto const &d : vm()->_devices)
          fprintf(f, " %s\n", d.path.c_str());
      }
    else
      {
        std::string devname;
        char const *params = strchrnul(cmd, ' ');

        if (params)
          {
            devname = std::string(cmd, params);
            ++params;
          }
        else
          {
            devname = cmd;
            params = "";
          }

        bool found_device = false;
        Cmd *monitor = nullptr;

        for (auto const &d : vm()->_devices)
          {
            if (d.path == devname)
              {
                found_device = true;
                monitor = dynamic_cast<Cmd *>(d.dev.get());
                break;
              }
          }

        if (found_device)
          {
            if (monitor)
              monitor->exec(f, params);
            else
              fprintf(f, "Not implemented\n");
          }
        else
          {
            fprintf(f, "Unknown device\n");
          }
      }
  }

private:
  T *vm() { return static_cast<T *>(this); }
  T const *vm() const { return static_cast<T const *>(this); }
};

}
