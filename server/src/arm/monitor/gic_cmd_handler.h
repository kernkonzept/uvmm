/*
 * Copyright (C) 2019-2020 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *            Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Gic_cmd_handler {};

template<typename T>
class Gic_cmd_handler<true, T> : public Cmd
{
public:
  Gic_cmd_handler()
  { register_toplevel("gic"); }

  char const *help() const override
  { return "GIC distributor"; }

  void exec(FILE *f, Arglist *) override
  {
    fprintf(f, "#\n# Spis\n#\n");
    fprintf(f, "Irq ena pen act pri con grp -> tar vcpu\n");
    for (unsigned i = 0; i < dist()->tnlines * 32; ++i)
      show_irq(f, dist()->_spis[i], i);
  }

private:
  template<typename I>
  void show_irq(FILE *f, I const &irq, int num)
  {
    if (!irq.enabled() && !irq.pending() && !irq.active())
      return;

    fprintf(f, "%3d   %c   %c   %c %3d %3d %3d    %3d %4d\n",
            num,
            irq.enabled() ? 'y' : 'n',
            irq.pending() ? 'y' : 'n',
            irq.active()  ? 'y' : 'n',
            static_cast<int>(irq.prio()),
            static_cast<int>(irq.config()),
            static_cast<int>(irq.group()),
            static_cast<int>(irq.target()),
            static_cast<int>(irq.cpu())
            );
  }

  T *dist()
  { return static_cast<T *>(this); }
};

}
