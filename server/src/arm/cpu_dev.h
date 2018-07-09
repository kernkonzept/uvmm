/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "generic_cpu_dev.h"

#include <cstdio>

extern __thread unsigned vmm_current_cpu_id;

namespace Vmm {

class Cpu_dev : public Generic_cpu_dev
{
public:
  // The ARM GIC has a hard architectural limit of 8 CPUs.
  enum { Max_cpus = 8 };

  enum
  {
    Flags_default_32 = 0x1d3,
    Flags_default_64 = 0x1c5,
    Flags_mode_32 = (1 << 4)
  };

  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *);

  void show_state_registers(FILE *f);

  void
  start_vcpu()
  {
    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Initiating cpu startup @ 0x%lx\n", _vcpu->r.ip);
    reschedule();
  }

  void init_vgic(void *vcpu);

  /**
   * Enter the virtual machine
   *
   * We assume an already setup register state that can be used as is
   * to enter the virtual machine (it was not changed by
   * vcpu_control_ext()). The virtualization related state is set to
   * default values, therefore we have to initialize this state here.
   */
  void reset() override;

  /**
   * Translate a device tree "reg" value to an internally usable CPU id.
   *
   * For most architectures this is NOP, but some archictures like ARM
   * might encode topology information into this value, which needs to
   * be translated.
   */
  static unsigned dtid_to_cpuid(l4_umword_t prop_val);

  bool matches(l4_umword_t hwid)
  { return hwid == _dt_affinity; }

private:
  enum
  {
    // define bits as 64 bit constants to make them usable in both
    // 32/64 contexts
    Mpidr_mp_ext    = 1ULL << 31,
    Mpidr_up_sys    = 1ULL << 30,
    Mpidr_mt_sys    = 1ULL << 24,
    Mpidr_aff_mask  = (0xffULL << 32) | 0xfffULL,
  };
  l4_umword_t _dt_affinity;
};

}
