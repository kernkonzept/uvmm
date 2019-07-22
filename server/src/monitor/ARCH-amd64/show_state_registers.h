/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include "cpu_dev.h"

namespace Monitor {

inline void show_state_registers(Vmm::Cpu_dev *cpu_dev, FILE *f)
{
  auto vcpu = cpu_dev->vcpu();
  auto regs = vcpu->r;
  auto *vms = vcpu.vm_state();

  fprintf(f,
          "RAX %lx\nRBX %lx\nRCX %lx\nRDX %lx\nRSI %lx\nRDI %lx\n"
          "RSP %lx\nRBP %lx\nR8 %lx\nR9 %lx\nR10 %lx\nR11 %lx\n"
          "R12 %lx\nR13 %lx\nR14 %lx\nR15 %lx\nRIP %lx\n",
          regs.ax, regs.bx, regs.cx, regs.dx, regs.si, regs.di, regs.sp,
          regs.bp, regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13,
          regs.r14, regs.r15, vms->ip());
}

}
