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
#include <type_traits>

#include "device.h"
#include "monitor/monitor.h"
#include "monitor/monitor_arch.h"
#include "monitor/monitor_args.h"

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

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'dev list': list available devices\n"
               "* 'dev <dev> <args>': execute device specific command\n",
            help());
  }

  void complete(FILE *f, Completion_request *compl_req) const override
  {
    compl_req->complete(f, {"list", "memmap", "iomap"});

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
    else if (*args == "memmap")
      dump_memmap(f);
    else if (*args == "iomap")
      dump_iomap<has_iomap()>(f);
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
  void dump_memmap(FILE *f)
  {
    for (auto const &p : *vm()->vmm()->memmap())
      {
        print_region(f, p.first, p.second.get());
        fputc('\n', f);
      }
  }

  template<bool HAS_IOMAP>
  typename std::enable_if<HAS_IOMAP>::type
  dump_iomap(FILE *f)
  {
    for (auto const &p : *vm()->vmm()->iomap())
      {
        print_region(f, p.first, p.second.get());
        fputc('\n', f);
      }
  }

  template<bool HAS_IOMAP>
  typename std::enable_if<!HAS_IOMAP>::type
  dump_iomap(FILE *f)
  { fprintf(f, "No iomap\n"); }

  template<typename U>
  void print_region(FILE *f, U const &region, Vdev::Dev_ref const *dev) const
  {
    enum { Region_id_maxlen = 7 };

    char const *region_type = "Untyped";

    switch (region.type)
      {
        case Vmm::Region_type::Ram:
          region_type = "RAM";
          break;
        case Vmm::Region_type::Vbus:
          region_type = "Vbus";
          break;
        case Vmm::Region_type::Kernel:
          region_type = "Kernel";
          break;
        case Vmm::Region_type::Virtual:
          region_type = "Virtual";
          break;
        default:
          break;
      }

    fprintf(f, "%-*s", Region_id_maxlen + 1, region_type);

    char const *region_fmt =
      sizeof(l4_addr_t) == 4 ? "[0x%08x...0x%08x]"
                             : "[0x%016llx...0x%016llx]";

    fprintf(f, region_fmt, region.start, region.end);

    // append device info (currently only works for some regions/devices)
    for (auto const &d : vm()->_devices)
      {
        if (d.dev.get() == dev)
          {
            fprintf(f, " (%s)", d.path.c_str());
            break;
          }
      }
  }

  T const *vm() const
  { return static_cast<T const *>(this); }
};

}
