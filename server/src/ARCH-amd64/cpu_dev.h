/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "generic_cpu_dev.h"
#include "debug.h"
#include "vcpu_ptr.h"

namespace Vmm {

class Cpu_dev : public Generic_cpu_dev
{
public:
  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *)
  : Generic_cpu_dev(idx, phys_id)
  {}

  void reset() override
  {
    Dbg().printf("Reset called\n");

    _vcpu->state = L4_VCPU_F_FPU_ENABLED;
    _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED | L4_VCPU_F_USER_MODE;

    _vcpu.reset();
  }

  void show_state_registers(FILE *f)
  {
    l4_vcpu_regs_t regs = _vcpu->r;
    fprintf(f, "RAX %lx\nRBX %lx\nRCX %lx\nRDX %lx\nRSI %lx\nRDI %lx\n"
               "RSP %lx\nRBP %lx\nR8 %lx\nR9 %lx\nR10 %lx\nR11 %lx\n"
               "R12 %lx\nR13 %lx\nR14 %lx\nR15 %lx\n",
               regs.ax, regs.bx, regs.cx, regs.dx, regs.si, regs.di, regs.sp,
               regs.bp, regs.r8, regs.r9, regs.r10, regs.r11, regs.r12,
               regs.r13, regs.r14, regs.r15);
  }

  /**
   * Translate a device tree "reg" value to an internally usable CPU id.
   *
   * For most architectures this is NOP, but some archictures like ARM
   * might encode topology information into this value, which needs to
   * be translated.
   */
  static unsigned dtid_to_cpuid(l4_int32_t prop_val)
  { return prop_val; }

}; // class Cpu_dev

} // namespace Vmm
