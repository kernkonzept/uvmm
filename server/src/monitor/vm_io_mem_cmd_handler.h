/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include <l4/sys/l4int.h>

#include "mem_types.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, bool, typename T>
class Vm_io_mem_cmd_handler {};

template<bool IO, typename T>
class Vm_io_mem_cmd_handler<IO, true, T> : public Cmd
{
  enum { Region_id_maxlen = 7 };

public:
  Vm_io_mem_cmd_handler()
  { register_toplevel(IO ? "iomap" : "memmap"); }

  char const *help() const override
  { return IO ? "IO device mappings" : "MMIO device mappings"; }

  void exec(FILE *f, Arglist *) override
  {
    fprintf(f, "Devices mapped at:\n");

    for (auto const &p : *mem())
      {
        print_region(f, p.first);
        fputc('\n', f);
      }
  }

private:
  template<typename U>
  static void print_region(FILE *f, U const &region)
  {
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

    char const *region_addr_fmt =
      sizeof(l4_addr_t) == 4 ? "[0x%08x...0x%08x]"
                             : "[0x%016llx...0x%016llx]";

    fprintf(f, region_addr_fmt, region.start, region.end);
  }

  T const *mem() const
  { return static_cast<T const *>(this); }
};

template<bool ENABLED, typename T>
using Vm_mem_cmd_handler = Vm_io_mem_cmd_handler<false, ENABLED, T>;

template<bool ENABLED, typename T>
using Io_mem_cmd_handler = Vm_io_mem_cmd_handler<true, ENABLED, T>;

}
