/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include <cassert>
#include <thread-l4>
#include <pthread-l4.h>

#include <l4/sys/debugger.h>
#include <l4/sys/scheduler>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/unique_cap>

#include "debug.h"
#include "virtual_timer.h"

static Dbg info(Dbg::Cpu, Dbg::Info, "vtimer");

namespace Vdev {

namespace
{
  enum : l4_uint32_t
  {
    Microsec_per_sec = 1000000,
  };
}

l4_uint32_t Virtual_timer::_us_to_ticks;

void Virtual_timer::init_frequency()
{
  // TODO: Rework frequency conversion and get_cur_time(), maybe use kernel
  // provided time accessor functions like on other architectures? Or scaling
  // math similar to arm/core_timer.h?
  l4_uint32_t frequency = l4re_kip()->platform_info.arch.timebase_frequency;
  assert(Microsec_per_sec <= frequency);
  assert(frequency % Microsec_per_sec == 0);
  _us_to_ticks = frequency / Microsec_per_sec;
  info.printf("Virtual_timer: us_to_ticks = %u\n", _us_to_ticks);
}

void Virtual_timer::run_timer(unsigned vcpu_no, unsigned phys_cpu_id)
{
  // Assign a higher priority to the timer thread so that it can interrupt the
  // vCPU thread to timely deliver timer interrupts.
  l4_sched_param_t sp = l4_sched_param(3);
  sp.affinity = l4_sched_cpu_set(phys_cpu_id, 0);
  auto sched = L4Re::Env::env()->scheduler();
  L4Re::chksys(sched->run_thread(Pthread::L4::cap(pthread_self()), sp),
               "Run timer thread.");

  info.printf("Hello Timer on CPU %u\n", vcpu_no);
  char buf[17];
  snprintf(buf, sizeof(buf), "vtimer%u", vcpu_no);
  l4_debugger_set_object_name(Pthread::L4::cap(pthread_self()).cap(), buf);

  // Wait for initial wakeup (timer is set the first time)
  auto e = l4_error(_wakeup_irq->receive(L4_IPC_NEVER));

  info.printf("Received initial timer thread wakeup on CPU %u! (%ld)\n",
               vcpu_no, e);

  // now loop forever
  while(1)
    {
      l4_timeout_t wait_timeout = L4_IPC_NEVER;

      l4_uint64_t next_event = next_event_exchange(Invalid_timer_value);
      // Woken up because the receive timeout expired
      if(L4_LIKELY(next_event == Invalid_timer_value))
        {
          _vcpu_ic->notify_timer();
        }
      else
        {
          // vCPU updated _next_event while we were sleeping.
          if (!setup_event_rcv_timeout(l4_utcb(), &wait_timeout, next_event))
            {
              // Next event already expired.
              _vcpu_ic->notify_timer();
            }
        }

      _wakeup_irq->receive(wait_timeout);
    }
}

void Virtual_timer::start_timer_thread(unsigned phys_cpu_id)
{
  _wakeup_irq = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                             "Allocate timer wakeup irq.");
  L4Re::chksys(L4Re::Env::env()->factory()->create(_wakeup_irq.get()),
               "Create timer wakeup irq.");

  next_event_store(Invalid_timer_value);
  _thread = std::thread(&Virtual_timer::run_timer, this,
                        _vcpu.get_vcpu_id(), phys_cpu_id);

  L4Re::chksys(_wakeup_irq->bind_thread(std::L4::thread_cap(_thread), 0),
               "Bind timer wakeup irq.");
}

void Virtual_timer::set_next_event(l4_uint64_t next_event)
{
  // Clamp next event to Max_timer_value
  if(next_event == Invalid_timer_value)
    next_event = Max_timer_value;

  next_event_store(next_event);

  // Notify timer thread that next_event was changed.
  _wakeup_irq->trigger();
}

bool Virtual_timer::setup_event_rcv_timeout(l4_utcb_t *utcb,
                                            l4_timeout_t *wait_timeout,
                                            l4_uint64_t event_time)
{
  l4_cpu_time_t cur_time_us = get_cur_time();
  l4_uint64_t next_event_us = event_time / _us_to_ticks;
  if (L4_LIKELY(next_event_us > cur_time_us))
    {
      // Program next timeout
      l4_rcv_timeout(l4_timeout_abs_u(next_event_us, 8, utcb), wait_timeout);
      return true;
    }
  else
    return false;
}

l4_cpu_time_t Virtual_timer::get_cur_time()
{
  // TODO: Directly read the time csr to get a more up-to-date reading?
  // Could save some unecessary IPC sleep operations, and we do not
  // have to convert the next_event to micro seconds in run_timer()
  // before testing.
  return l4_kip_clock(l4re_kip());
}

#if __riscv_xlen == 32
// We don't have 64-bit atomic instructions on RV32.
void Virtual_timer::next_event_store(l4_uint64_t next_event)
{
  acquire_lock(std::L4::thread_cap(_thread));
  _next_event = next_event;
  release_lock();
}

l4_uint64_t Virtual_timer::next_event_exchange(l4_uint64_t next_event)
{
  acquire_lock(_vcpu_thread);
  l4_uint64_t prev_next_event = _next_event;
  _next_event = next_event;
  release_lock();
  return prev_next_event;
}

void Virtual_timer::acquire_lock(L4::Cap<L4::Thread> contender)
{
  // Acquire lock
  while (L4_UNLIKELY(_next_event_lock.test_and_set(std::memory_order_acquire)))
    {
      // Both the vCPU and the timer thread run on the same physical cpu,
      // therefore we switch immediately to the contending thread.
      contender->switch_to();
    }
}

void Virtual_timer::release_lock()
{
  // Release lock
  _next_event_lock.clear(std::memory_order_release);
}
#else
void Virtual_timer::next_event_store(l4_uint64_t next_event)
{
  _next_event.store(next_event, std::memory_order_relaxed);
}

l4_uint64_t Virtual_timer::next_event_exchange(l4_uint64_t next_event)
{
  return _next_event.exchange(next_event, std::memory_order_relaxed);
}
#endif

}
