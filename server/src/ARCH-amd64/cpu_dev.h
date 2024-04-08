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

#include <deque>
#include <mutex>

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
    Sleeping = 1, // Startup state, Thread created but not running,
                  // needs rescheduling.
    Stopped,      // Waits for INIT signal, no need for rescheduling.
    Init,         // Wait for SIPI to transition to Running.
    Halted,       // Idle state, VMentry only on event.
    Running
  };

private:
  struct State_change
  {
    State_change(Cpu_state s) : target_state(s) {}
    Cpu_state target_state;
  };

  struct Ipi_event
  {
    Ipi_event(Cpu_dev *c) : cpu(c) {}
    void act()
    {
      cpu->_check_msgq = true;
    }

    void registration_failure()
    {
      Dbg().printf("Failed to register IRQ to for IPI; "
                   "vCPU %u cannot be started.\n", cpu->vcpu().get_vcpu_id());
    }

    void trigger_failure(long ipc_err)
    {
      Dbg().printf("IPI to vCPU %u failed with error %li\n",
                   cpu->vcpu().get_vcpu_id(), ipc_err);
    }

    Cpu_dev *cpu;
  };

public:
  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *)
  : Generic_cpu_dev(idx, phys_id),
    _ipi(Ipi_event(this))
  {
    _cpu_state = (idx == 0) ? Running : Sleeping;
  }

  ~Cpu_dev()
  {
    Vcpu_obj_registry *reg = _vcpu.get_ipc_registry();
    _ipi.disarm(reg);
  }

  void powerup_cpu() override
  {
    Generic_cpu_dev::powerup_cpu();
    _ipi.arm(_vcpu.get_ipc_registry());
  }

  /// Reset the Cpu_dev including vCPU does not return to the caller.
  void reset() override
  {
    vmm_current_cpu_id = _vcpu.get_vcpu_id();
    info().printf("[%3u] Reset called\n", vmm_current_cpu_id);

    reset_common();
    wait_until_online();

    info().printf("[%3u] Resetting vCPU.\n", vmm_current_cpu_id);
    _vcpu.reset(_protected_mode);
  }

  void hot_reset()
  {
    // assumption: Guest::run_vm() already called once.
    // intention: Do not add leak stack memory.
    reset_common();

    info().printf("[%3u] Hot resetting vCPU.\n", vmm_current_cpu_id);
    _vcpu.hot_reset();

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
  {
    Cpu_state s = get_cpu_state();
    return (s == Cpu_state::Running) || (s == Cpu_state::Halted);
  }

  void set_cpu_state(Cpu_state state)
  { _cpu_state = state; }

  void set_protected_mode()
  { _protected_mode = true; }

  /**
   * Handle the stop event.
   *
   * The event is usually emitted cross core, but also used in CPU local
   * error cases.
   */
  void stop() override
  {
    _stop_irq.disarm(_vcpu.get_ipc_registry());

    {
      std::lock_guard<std::mutex> lock(_message_q_lock);
      // Clear all pending state changes to ensure the core is stopped ASAP.
      _message_q.clear();
      _message_q.emplace_back(Cpu_state::Stopped);
    }
    _check_msgq = true;
    // Do not do anything blocking here, we need to finish the execution of the
    // IPC dispatching that brought us here or return to our local caller.
  }

  /// core local request to halt the CPU.
  void halt_cpu()
  {
    {
      std::lock_guard<std::mutex> lock(_message_q_lock);
      _message_q.emplace_back(Cpu_state::Halted);
    }
    _check_msgq = true;
    // No IRQ trigger, we are already in VMexit handling
  }

  /// Send cross-core INIT signal
  void send_init_ipi()
  {
    {
      std::lock_guard<std::mutex> lock(_message_q_lock);
      _message_q.emplace_back(Cpu_state::Init);
    }
    _ipi.trigger();
  }

  /// Send cross-core SIPI signal
  void send_sipi()
  {
    {
      std::lock_guard<std::mutex> lock(_message_q_lock);
      _message_q.emplace_back(Cpu_state::Running);
    }
    _ipi.trigger();
  }

  bool has_message() const { return _check_msgq; }

  Cpu_state next_state()
  {
    if (!has_message())
      return get_cpu_state();

    std::lock_guard<std::mutex> lock(_message_q_lock);
    if (_message_q.empty())
      {
        _check_msgq = false;
        return get_cpu_state();
      }
    Cpu_state new_state = _message_q.front().target_state;
    _message_q.pop_front();
    _check_msgq = !_message_q.empty();

    return new_state;
  }

  l4_msgtag_t wait_for_ipi()
  {
    l4_msgtag_t tag = _ipi.receive();
    _check_msgq = true;

    return tag;
  }

private:
  static Dbg info() { return Dbg(Dbg::Cpu, Dbg::Info, "Cpu_dev"); }

  /// Wait until an IPI puts the CPU in online state.
  void wait_until_online()
  {
    while (has_message())
      set_cpu_state(next_state());

    // wait for the SIPI to sets the `Running` state
    while (!cpu_online())
      {
        wait_for_ipi();

        while (has_message())
          set_cpu_state(next_state());
      }
  }

  /// Functionality performed to reset a vCPU.
  void reset_common()
  {
    _stop_irq.arm(_vcpu.get_ipc_registry());

    _vcpu->state = L4_VCPU_F_FPU_ENABLED;
    _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED | L4_VCPU_F_USER_MODE;
  }

  std::atomic<Cpu_state> _cpu_state; // core-local writes; cross-core reads;
  bool _protected_mode = false;
  bool _check_msgq = false; // use only in local vCPU thread.

  Cpu_irq<Ipi_event> _ipi;
  // The mutex is used in IPI cases (INIT, SIPI, STOP) and for the local HALT
  // event. The IPIs do not happen during normal operation, HALT happens when
  // the core has nothing to do and reacts only to IRQs. In all other VMexits,
  // this mutex is unused.
  std::mutex _message_q_lock;
  std::deque<State_change> _message_q;
}; // class Cpu_dev

} // namespace Vmm
