/*
 * Copyright (C) 2019 Kernkonzept GmbH.
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
    fprintf(f, "Irq     raw pen act ena tar pri con grp\n");
    for (unsigned i = 0; i < dist()->tnlines * 32; ++i)
      show_irq(f, dist()->_spis[i], i);
  }

private:
  template<typename I>
  void show_irq(FILE *f, I const &irq, int num)
  {
    if (!irq.enabled())
      return;

    auto *p = irq._p;

    fprintf(f, "%3d %x  %c   %c   %c  %3d %3d %3d %3d\n",
            num, p->_state,
            p->pending() ? 'y' : 'n',
            p->active()  ? 'y' : 'n',
            p->enabled() ? 'y' : 'n',
            (int)p->target(),
            (int)p->prio(),
            (int)p->config(),
            (int)p->group());
  }

  T *dist()
  { return static_cast<T *>(this); }
};

}
