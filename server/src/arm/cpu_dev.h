/*
 * Copyright (C) 2017-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <atomic>

#include "generic_cpu_dev.h"
#include "monitor/cpu_dev_cmd_handler.h"

extern __thread unsigned vmm_current_cpu_id;

namespace Vmm {

class Cpu_dev
: public Generic_cpu_dev,
  public Monitor::Cpu_dev_cmd_handler<Monitor::Enabled, Cpu_dev>
{
  /**
   * Trivial interrupt to wakeup stopped vCPU.
   */
  struct Restart_event : public L4::Irqep_t<Restart_event>
  {
  public:
    void handle_irq() {}
  };

public:
  // CPU 255 is used as "invalid CPU" by the GIC code...
  enum { Max_cpus = 254 };

  enum
  {
    Flags_default_32 = 0x1d3,
    Flags_default_64 = 0x1c5,
    Flags_mode_32 = (1 << 4)
  };

  /**
   * CPU states according to the PSCI spec
   */
  enum class Cpu_state
  {
    Off,
    On_pending,
    On_prepared,
    On
  };

  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *);

  void powerup_cpu() override;

  bool
  start_vcpu()
  {
    if (online_state() != Cpu_state::On_pending)
      {
        // Should we convert this to an assert()?
        Err().printf("%s: CPU%d not in On_pending state", __func__, _phys_cpu_id);
        return false;
      }

    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Initiating cpu startup @ 0x%lx\n", _vcpu->r.ip);

    if (_vcpu->entry_sp && !restart())
      {
        mark_off();
        return false;
      }
    else
      reschedule();

    return true;
  }

  /**
   * Enter the virtual machine
   *
   * We assume an already setup register state that can be used as is
   * to enter the virtual machine (it was not changed by
   * vcpu_control_ext()). The virtualization related state is set to
   * default values, therefore we have to initialize this state here.
   */
  void L4_NORETURN reset() final override;

  /**
   * Restart a CPU
   *
   * Restarts a stopped CPU and enters the virtual machine using reset().
   *
   * \return Returns true if restart was successful, false otherwise.
   */
  bool restart();

  /**
   * Stop a CPU
   */
  void L4_NORETURN stop() override;

  /**
   * Get the online state of a CPU.
   */
  Cpu_state online_state() const
  { return std::atomic_load(&_online); }

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
    return std::atomic_compare_exchange_strong(&_online, &expected,
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
    std::atomic_store(&_online, Cpu_state::On_prepared);
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
    std::atomic_store(&_online, Cpu_state::Off);
  }

  /**
   * Mark CPU as On.
   *
   * Marks the CPU as On. The current state has to be On_pending or On_prepared.
   */
  void mark_on()
  {
    assert(online_state() == Cpu_state::On_pending ||
           online_state() == Cpu_state::On_prepared);
    std::atomic_store(&_online, Cpu_state::On);
  }

  /**
   * Translate a device tree "reg" value to an internally usable CPU id.
   *
   * For most architectures this is NOP, but some archictures like ARM
   * might encode topology information into this value, which needs to
   * be translated.
   */
  static unsigned dtid_to_cpuid(l4_umword_t) { return 0; }
  static bool has_fixed_dt_mapping() { return false; }

  bool matches(l4_umword_t hwid)
  { return hwid == _dt_affinity; }

  bool matches(l4_umword_t hwid, char lvl)
  {
    l4_umword_t mask = ~0UL << (lvl * 8);
    return ((hwid ^ _dt_affinity) & mask) == 0;
  }

  l4_uint32_t affinity() const
  { return _dt_affinity; }

private:
  enum
  {
    // define bits as 64 bit constants to make them usable in both
    // 32/64 contexts
    Mpidr_mp_ext    = 1ULL << 31,
    Mpidr_up_sys    = 1ULL << 30,
    Mpidr_mt_sys    = 1ULL << 24,
    // Affinity Aff{0,1,2} in [23-0], Aff3 in [39-32]
    Mpidr_aff_mask  = (0xffULL << 32) | 0xffffffULL,
  };
  l4_umword_t _dt_affinity;
  l4_umword_t _dt_vpidr = 0;
  std::atomic<Cpu_state> _online{Cpu_state::Off};
  Restart_event _restart_event;
  bool _pmsa = false;
};

}
