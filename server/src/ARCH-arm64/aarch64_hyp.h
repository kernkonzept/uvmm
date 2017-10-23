/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <arm_hyp.h>

namespace Vmm { namespace Arm {

struct State
{
  struct Regs
  {
    l4_uint64_t hcr;

    l4_uint32_t sctlr;
    l4_uint32_t cntkctl;
    l4_uint32_t mdcr;
    l4_uint32_t mdscr;
  };

  typedef Gic_t<4> Gic;

  Regs vm_regs;
  Regs host_regs;
  Gic  gic;

  l4_uint64_t vmpidr;
  l4_uint64_t cntvoff;

  l4_uint64_t cntv_cval;
  l4_uint32_t cntkctl;
  l4_uint32_t cntv_ctl;

  void arch_setup(bool guest_64bit)
  {
    if (guest_64bit)
      vm_regs.hcr |= 1UL << 31; // set RW bit
    vm_regs.mdcr = (1 << 9) /*TDA*/;
  }
};

inline State *
vm_state(l4_vcpu_state_t *vcpu)
{
  return reinterpret_cast<State *>(reinterpret_cast<char *>(vcpu) + L4_VCPU_OFFSET_EXT_STATE);
}

}}
