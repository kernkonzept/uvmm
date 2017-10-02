/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "cpu_dev.h"
#include "gic.h"

namespace Vmm
{

void
Cpu_dev::init_vgic(Vmm::Arm::State::Gic *iface)
{ Gic::Dist::init_vgic(iface); }

void
Cpu_dev::show_state_registers(FILE *f)
{
  Vcpu_ptr vcpu = _vcpu;

  for (unsigned i = 0; i < 31; ++i)
    fprintf(f, "x%2d:%16lx%s", i, vcpu->r.r[i], (i % 4) == 3 ? "\n" : "  ");

  fprintf(f, "\n");
  fprintf(f, "pc=%lx  sp=%lx  psr=%lx  sctlr=%x\n",
          vcpu->r.ip, vcpu->r.sp, vcpu->r.flags,
          vcpu.state()->vm_regs.sctlr);
}

} // namespace
