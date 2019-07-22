/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include <l4/sys/vcpu.h>

#include "cpu_dev.h"

namespace Monitor {

inline void show_state_registers(Vmm::Cpu_dev *cpu_dev, FILE *f)
{
  auto vcpu = cpu_dev->vcpu();

  for (unsigned i = 0; i < 31; ++i)
    fprintf(f, "x%2d:%16lx%s", i, vcpu->r.r[i], (i % 4) == 3 ? "\n" : "  ");

  fprintf(f, "\n");
  fprintf(f, "pc=%lx  sp=%lx  psr=%lx  sctlr=%x\n",
          vcpu->r.ip, vcpu->r.sp, vcpu->r.flags,
          l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR));
}

}
