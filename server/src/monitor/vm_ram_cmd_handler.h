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

#include <l4/sys/l4int.h>

#include "monitor.h"
#include "monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Vm_ram_cmd_handler {};

template<typename T>
class Vm_ram_cmd_handler<true, T> : public Cmd
{
public:
  Vm_ram_cmd_handler()
  { register_toplevel("ram"); }

  char const *help() const override
  { return "RAM dataspaces"; }

  void exec(FILE *f, Arglist *) override
  {
    fprintf(f, "Dataspace  Guest area             Size        Local address  Phys?\n");
    for (auto const &r : vm_ram()->_regions)
      fprintf(f, "%9lu  0x%08llx-0x%08llx  0x%08llx  0x%08llx     %s\n",
              r.ds().cap() >> L4_CAP_SHIFT,
              (l4_uint64_t)r.vm_start().get(),
              (l4_uint64_t)(r.vm_start().get() + r.size()),
              (l4_uint64_t)r.size(),
              (l4_uint64_t)r.local_start(),
              r.has_phys_addr() ? "Y" : "N");
  }

private:
  T *vm_ram()
  { return static_cast<T *>(this); }
};

}
