/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "debug.h"
#include "generic_cpu_dev.h"
#include "vcpu_ptr.h"
#include "monitor/cpu_dev_cmd_handler.h"

namespace Vmm {

class Cpu_dev
: public Generic_cpu_dev,
  public Monitor::Cpu_dev_cmd_handler<Monitor::Enabled, Cpu_dev>
{
public:
  enum { Max_cpus = 8 };

  enum Cpu_state
  {
    Sleeping,
    Init,
    Init_level_de_assert,
    Startup,
    Running
  };

  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *)
  : Generic_cpu_dev(idx, phys_id)
  {
    _cpu_state = (idx == 0) ? Running : Sleeping;
  }

  void reset() override
  {
    Dbg().printf("Reset called\n");

    _vcpu->state = L4_VCPU_F_FPU_ENABLED;
    _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED | L4_VCPU_F_USER_MODE;

    _vcpu.reset();
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

  static bool has_fixed_dt_mapping() { return true; }

  unsigned get_phys_cpu_id() const noexcept
  { return _phys_cpu_id; }

  Cpu_state get_cpu_state()
  { return _cpu_state; }

  void set_cpu_state(Cpu_state state)
  { _cpu_state = state; }

private:
  Cpu_state _cpu_state;

}; // class Cpu_dev

} // namespace Vmm
