/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "vcpu_array.h"

namespace Vmm
{

void
Vcpu_array::show_state_registers(FILE *f)
{
  for (int i = 0; i < Max_cpus; ++i)
    {
      if (!_cpus[i])
        continue;

      // if (i != current_cpu)
      //  interrupt_vcpu(i);

      Cpu v = _cpus[i]->vcpu();
      fprintf(f, "CPU %d:\n", i);
      fprintf(f, "pc=%08lx lr=%08lx sp=%08lx flags=%08lx\n", v->r.ip, v->r.lr,
              v->r.sp, v->r.flags);
      fprintf(f, " r0=%08lx  r1=%08lx  r2=%08lx  r3=%08lx\n", v->r.r[0],
              v->r.r[1], v->r.r[2], v->r.r[3]);
      fprintf(f, " r4=%08lx  r5=%08lx  r6=%08lx  r7=%08lx\n", v->r.r[4],
              v->r.r[5], v->r.r[6], v->r.r[7]);
      fprintf(f, " r8=%08lx  r9=%08lx r10=%08lx r11=%08lx\n", v->r.r[8],
              v->r.r[9], v->r.r[10], v->r.r[11]);
      fprintf(f, "r12=%08lx\n", v->r.r[12]);
    }
}

} // namespace
