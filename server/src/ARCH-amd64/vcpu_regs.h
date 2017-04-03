/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/vcpu/vcpu.h>

#include "debug.h"

namespace Vmm { namespace Vcpu {

struct Regs : public l4_vcpu_regs_t
{
  int handle_hardware_exception(unsigned num)
  {
    Err err;
    err.printf("Hardware exception\n");

    switch (num)
    {
      case 0: err.printf("Divide error\n"); break;
      case 1: err.printf("Debug\n"); break;
      case 3: err.printf("Breakpoint\n"); break;
      case 4: err.printf("Overflow\n"); break;
      case 5: err.printf("Bound range\n"); break;
      case 6: err.printf("Invalid opcode\n"); break;
      case 7: err.printf("Device not available\n"); break;
      case 8: err.printf("Double fault\n"); break;
      case 9: err.printf("Coprocessor segment overrun\n"); break;
      case 10: err.printf("Invalid TSS\n"); break;
      case 11: err.printf("Segment not present\n"); break;
      case 12: err.printf("Stack-segment fault\n"); break;
      case 13: err.printf("General protection\n"); break;
      case 14: err.printf("Page fault\n"); break;
      case 16 : err.printf("FPU error\n"); break;
      case 17: err.printf("Alignment check\n"); break;
      case 18: err.printf("Machine check\n"); break;
      case 19: err.printf("SIMD error\n"); break;
      default: err.printf("Unknown exception\n"); break;
    }
    return -L4_EINVAL;
  }

};

} } // namespace
