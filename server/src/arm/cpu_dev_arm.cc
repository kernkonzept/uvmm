/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "cpu_dev.h"
#include "cpu_dev_subarch.h"

extern "C" void vcpu_entry(l4_vcpu_state_t *vcpu);

namespace Vmm {

void
Cpu_dev::reset()
{
  // set thread local cpu id
  vmm_current_cpu_id = _vcpu.get_vcpu_id();

  //
  // initialize hardware related virtualization state
  //
  auto *vm = _vcpu.state();

  init_vgic(&vm->gic);

  // we set FB, and BSU to inner sharable to tolerate migrations
  vm->vm_regs.hcr = 0x30023f; // VM, PTW, AMO, IMO, FMO, FB, SWIO, TIDCP, TAC
  vm->vm_regs.hcr |= 1UL << 10; // BUS = inner sharable
  vm->vm_regs.hcr |= 3UL << 13; // Trap WFI and WFE

  // set C, I, CP15BEN
  vm->vm_regs.sctlr = (1UL << 5) | (1UL << 2) | (1UL << 12);

  vm->arch_setup(!(_vcpu->r.flags & Flags_mode_32));

  //
  // Initialize vcpu state
  //
  _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED
    | L4_VCPU_F_USER_MODE
    | L4_VCPU_F_IRQ
    | L4_VCPU_F_PAGE_FAULTS
    | L4_VCPU_F_EXCEPTIONS;
  _vcpu->entry_ip = (l4_umword_t) &vcpu_entry;
  // entry_sp is derived from thread local stack pointer
  asm volatile ("mov %0, sp" : "=r"(_vcpu->entry_sp));

  Dbg().printf("Starting Cpu%d @ 0x%lx %dBit mode "
               "(handler @ %lx, stack: %lx, task: %lx)\n",
               vmm_current_cpu_id, _vcpu->r.ip,
               _vcpu->r.flags & Flags_mode_32 ? 32 : 64,
               _vcpu->entry_ip, _vcpu->entry_sp, _vcpu->user_task);

  L4::Cap<L4::Thread> myself;
  myself->vcpu_resume_commit(myself->vcpu_resume_start());
  // XXX Error handling?
}

}
