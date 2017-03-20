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

// we enumerate the CPUs as they are listed in the device tree and
// boot on logical cpu 0
static unsigned logical_cpu_num = 0;

unsigned
Cpu_dev::dtid_to_cpuid(l4_umword_t)
{
  // ignore topology information and simply return the next logical
  // cpu number
  return logical_cpu_num++;
}

Cpu_dev::Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *node)
: Generic_cpu_dev(idx, phys_id)
{
  if (node)
    {
      int prop_size;
      auto *prop = node->get_prop<fdt32_t>("reg", &prop_size);
      if (prop && prop_size > 0)
        {
          _dt_affinity = node->get_prop_val(prop, prop_size, true);
          return;
        }
    }

  _dt_affinity = idx;
}

void
Cpu_dev::reset()
{
  // set thread local cpu id
  vmm_current_cpu_id = _vcpu.get_vcpu_id();

  //
  // initialize hardware related virtualization state
  //
  init_vgic(*_vcpu);

  // we set FB, and BSU to inner sharable to tolerate migrations
  l4_umword_t hcr = 0x30023f; // VM, PTW, AMO, IMO, FMO, FB, SWIO, TIDCP, TAC
  hcr |= 1UL << 10; // BUS = inner sharable
  hcr |= 3UL << 13; // Trap WFI and WFE
  l4_vcpu_e_write(*_vcpu, L4_VCPU_E_HCR, hcr);

  // set C, I, CP15BEN
  l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_SCTLR, (1UL << 5) | (1UL << 2) | (1UL << 12));

  // The type of vmpidr differs between ARM32 and ARM64, so we use 64
  // bit here as a superset.
  l4_uint64_t vmpidr = l4_vcpu_e_read(*_vcpu, L4_VCPU_E_VMPIDR);

  if (! (vmpidr &  Mpidr_mp_ext))
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Vmpidr: %llx - Missing multiprocessing extension\n", vmpidr);

  // remove mt/up bit and replace affinity with value from device tree
  l4_vcpu_e_write(*_vcpu, L4_VCPU_E_VMPIDR,
                  (vmpidr & ~(Mpidr_up_sys | Mpidr_mt_sys | Mpidr_aff_mask))
                  | (_dt_affinity & Mpidr_aff_mask));

  arm_subarch_setup(*_vcpu, !(_vcpu->r.flags & Flags_mode_32));

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

  Dbg().printf("Starting Cpu%d @ 0x%lx in %dBit mode (handler @ %lx,"
               " stack: %lx, task: %lx, mpidr: %llx (orig: %llx)\n",
               vmm_current_cpu_id, _vcpu->r.ip,
               _vcpu->r.flags & Flags_mode_32 ? 32 : 64,
               _vcpu->entry_ip, _vcpu->entry_sp, _vcpu->user_task,
               static_cast<l4_uint64_t>(l4_vcpu_e_read(*_vcpu, L4_VCPU_E_VMPIDR)),
               vmpidr);

  L4::Cap<L4::Thread> myself;
  myself->vcpu_resume_commit(myself->vcpu_resume_start());
  // XXX Error handling?
}

}
