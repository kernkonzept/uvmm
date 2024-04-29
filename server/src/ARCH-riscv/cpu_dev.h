/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *            Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <atomic>

#include "generic_cpu_dev.h"
#include "vcpu_ic.h"
#include "monitor/cpu_dev_cmd_handler.h"

namespace Vmm {

extern __thread unsigned vmm_current_cpu_id;

class Cpu_dev
: public Generic_cpu_dev,
  public Monitor::Cpu_dev_cmd_handler<Monitor::Enabled, Cpu_dev>
{
public:
  // Maximum number of CPUs that are addressable.
  enum { Max_cpus = 8 };

  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *node);

  /**
   * CPU states
   */
  enum class Cpu_state
  {
    Off,
    On_pending,
    On_prepared,
    On,
    Suspended,
  };

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

  // TODO: Starting and stopping of vCPUs is adopted from ARM,
  //       merging this functionality probably would be benefitial.
  bool start_vcpu();
  void L4_NORETURN stop_vcpu();
  bool restart_vcpu();


  void powerup_cpu() override;

  void L4_NORETURN reset() final override;
  void L4_NORETURN stop() override { stop_vcpu(); };

  /**
   * Get the online state of a CPU.
   */
  Cpu_state online_state() const
  { return std::atomic_load(&_cpu_state); }

  /**
   * Is the CPU online?
   */
  bool online() const
  { return online_state() != Cpu_state::Off; }

  /**
   * Cpu_state changes
   * * Off -> On_pending:          concurrent execution
   * * On_pending  -> On:          CPU local, no concurrency (initial startup)
   * * On_pending  -> On_prepared: CPU local, no concurrency (restart)
   * * On_prepared -> On:          CPU local, no concurrency (restart)
   * * On* -> Off:                 CPU local, no concurrency
   * * On -> Suspended:            CPU local, no concurrency
   * * Suspended -> On:            CPU local, no concurrency
   *
   * The only state change that requires protection against concurrent access
   * is the change from Off to On_pending. Therefore mark_pending() uses
   * compare/exchange, the other operation use a simple store.
   */

  /**
   * Mark CPU as On_pending.
   *
   * \retval True  Successfully changed state from Off to On_pending
   * \retval False  Failed to change the state from Off to On_pending,
   *                the state was already changed by someone else.
   */
  bool mark_on_pending()
  {
    // Atomically change state from Off to On_pending, see above
    Cpu_state expected{Cpu_state::Off};
    return std::atomic_compare_exchange_strong(&_cpu_state, &expected,
                                               Cpu_state::On_pending);
  }

  /**
   * Mark CPU as On_prepared.
   *
   * The vCPU entry has been setup and the guest is about to be entered
   * again. This state is only used when restarting a CPU that was previously
   * powered off.
   */
  void mark_on_prepared()
  {
    assert(online_state() == Cpu_state::On_pending);
    std::atomic_store(&_cpu_state, Cpu_state::On_prepared);
  }

  /**
   * Mark CPU as Off.
   *
   * Marks the CPU as Off. The current state has to be either On (CPU is
   * switched off) or On_pending (we failed to get the CPU up and fall
   * back to Off)
   */
  void mark_off()
  {
    assert(online_state() != Cpu_state::Off);
    std::atomic_store(&_cpu_state, Cpu_state::Off);
  }

  /**
   * Mark CPU as On.
   *
   * Marks the CPU as On. The current state has to be On_pending or On_prepared.
   */
  void mark_on()
  {
    assert(online_state() == Cpu_state::On_pending ||
           online_state() == Cpu_state::On_prepared ||
           online_state() == Cpu_state::Suspended);
    std::atomic_store(&_cpu_state, Cpu_state::On);
  }

  /**
   * Mark CPU as Suspended.
   *
   * Marks the CPU as Suspended. The current state has to be On.
   */
  void mark_suspended()
  {
    assert(online_state() == Cpu_state::On);
    std::atomic_store(&_cpu_state, Cpu_state::Suspended);
  }

  void set_vcpu_ic(cxx::Ref_ptr<Gic::Vcpu_ic> vcpu_ic)
  {
    _vcpu_ic = vcpu_ic;
  }

private:
  /**
   * Trivial interrupt to wakeup stopped vCPU.
   */
  struct Restart_event : public L4::Irqep_t<Restart_event>
  {
  public:
    void handle_irq() {}
  };

  cxx::Ref_ptr<Gic::Vcpu_ic> _vcpu_ic;
  std::atomic<Cpu_state> _cpu_state{Cpu_state::Off};
  Restart_event _restart_event;
};

}
