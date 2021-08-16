/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <atomic>
#include <thread>

#include <l4/util/util.h>

#include "vcpu_ic.h"

namespace Vdev {

/**
 * Per-vCPU virtual timer that uses a separate timer thread that blocks on an
 * IRQ receive operation with a timeout equal to the next timer event. When the
 * timeout expires, the timer thread notifies the Vcpu_ic of the vCPU that a
 * timer interrupt is pending.
 *
 * When the guest reconfigures the next event of its timer, the wakeup IRQ of
 * the timer thread is triggered, whereupon the timer thread is woken up, only
 * to block again in the IRQ receive operation with a timeout adjusted
 * according to the new next event.
 */
class Virtual_timer : public virtual Vdev::Dev_ref
{
public:
  Virtual_timer(Vmm::Vcpu_ptr vcpu, L4::Cap<L4::Thread> vcpu_thread,
                cxx::Ref_ptr<Gic::Vcpu_ic> vcpu_ic)
  : _vcpu(vcpu),
    _vcpu_thread(vcpu_thread),
    _vcpu_ic(vcpu_ic)
  {
  }

  virtual ~Virtual_timer() = default;

  /**
   * Start a new thread to run the timer loop.
   *
   * \param vcpu_no      Number of the vCPU to run the timer for.
   * \param phys_cpu_id  Scheduler id of the physical core to run on.
   */
  void start_timer_thread(unsigned phys_cpu_id);

  /**
   * Program the next timer event.
   *
   * \param next_event Next timer event in real-time clock cycles,
   *                   as for example returned by the rdtime instruction.
   */
  void set_next_event(l4_uint64_t next_event);

private:
  l4_cpu_time_t get_cur_time();

  /**
   * Migrate a vCPU's timer thread to its physical core and run the timer loop.
   *
   * \param vcpu_no      Number of the vCPU to run the timer for.
   * \param phys_cpu_id  Scheduler id of the physical core to run on.
   */
  void run_timer(unsigned vcpu_no, unsigned phys_cpu_id);

  /**
   * Atomically write the _next_event member.
   *
   * \param next_event  Value to store.
   *
   * \note Only called by vCPU thread.
   */
  void next_event_store(l4_uint64_t next_event);

  /**
   * Atomically exchange the value of _next_event member.
   *
   * \param next_event  New value.
   *
   * \return Old value.
   *
   * \note Only called by timer thread.
   */
  l4_uint64_t next_event_exchange(l4_uint64_t next_event);

  Vmm::Vcpu_ptr _vcpu;
  L4::Cap<L4::Thread> _vcpu_thread;
  cxx::Ref_ptr<Gic::Vcpu_ic> _vcpu_ic;

  l4_uint32_t _us_to_ticks;

  // The timer thread
  std::thread _thread;
  // Wakeup irq for the timer thread
  L4Re::Util::Unique_cap<L4::Irq> _wakeup_irq;

  enum : l4_uint64_t
  {
    Invalid_timer_value  = ~0ULL,
    Max_timer_value      = Invalid_timer_value - 1,
  };

#if __riscv_xlen == 32
  /**
   * RV32 does not have 64-bit atomic instructions, thus a lock is needed to
   * ensure atomic modifications of _next_event.
   *
   * _next_event is only accessed by two threads, the vCPU thread and the
   *  virtual timer thread for the vCPU. As both threads run on the same CPU,
   *  this lock implementation simply switches to the contending thread if it
   *  encounters a taken lock.
   *
   * \param contender Contending thread to switch to if the lock is already
   *                  taken.
   */
  void acquire_lock(L4::Cap<L4::Thread> contender);
  void release_lock();

  std::atomic_flag _next_event_lock = ATOMIC_FLAG_INIT;
  l4_uint64_t _next_event;
#else
  std::atomic<l4_uint64_t> _next_event;
#endif
};

}
