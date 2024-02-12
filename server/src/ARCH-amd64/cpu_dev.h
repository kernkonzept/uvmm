/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include <atomic>

#include "debug.h"
#include "generic_cpu_dev.h"
#include "vcpu_ptr.h"
#include "monitor/cpu_dev_cmd_handler.h"

extern __thread unsigned vmm_current_cpu_id;

namespace Vmm {

class Cpu_dev
: public Generic_cpu_dev,
  public Monitor::Cpu_dev_cmd_handler<Monitor::Enabled, Cpu_dev>
{
public:
  enum { Max_cpus = 128 };

  enum Cpu_state
  {
    Sleeping,
    Init,
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

    vmm_current_cpu_id = _vcpu.get_vcpu_id();
    _stop_irq.arm(_vcpu.get_ipc_registry());

    _vcpu->state = L4_VCPU_F_FPU_ENABLED;
    _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED | L4_VCPU_F_USER_MODE;

    _vcpu.reset(_protected_mode);
  }

  /**
   * Translate a device tree "reg" value to an internally usable CPU id.
   *
   * For most architectures this is NOP, but some architectures like ARM
   * might encode topology information into this value, which needs to
   * be translated.
   */
  static unsigned dtid_to_cpuid(l4_int32_t prop_val)
  { return prop_val; }

  static bool has_fixed_dt_mapping() { return true; }

  unsigned get_phys_cpu_id() const noexcept
  { return _phys_cpu_id; }

  Cpu_state get_cpu_state() const
  { return _cpu_state; }

  bool cpu_online() const
  { return get_cpu_state() == Cpu_state::Running; }

  void set_cpu_state(Cpu_state state)
  { _cpu_state = state; }

  void set_protected_mode()
  { _protected_mode = true; }

  virtual void stop() override
  {
    set_cpu_state(Sleeping);
    _stop_irq.disarm(_vcpu.get_ipc_registry());
    // Do not do anything blocking here, we need to finish the execution of the
    // IPC dispatching that brought us here.
  }

private:
  std::atomic<Cpu_state> _cpu_state;
  bool _protected_mode = false;

}; // class Cpu_dev

} // namespace Vmm
