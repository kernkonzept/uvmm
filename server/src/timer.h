/*
 * Copyright (C) 2017, 2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

/**
 * Timer infrastructure.
 *
 * On x86 there is no direct source of time available to user processes.
 * Instead we rely on IPC timeouts. This infrastructure instantiates a
 * timer-thread on each vCPU. The timer-thread implements an API for timer
 * device models to register callbacks together with a timestamp. The timer
 * thread will run the callbacks once the timestamp was reached. Typically the
 * callback will update device model-internal data structures and inject
 * interrupts accordingly.
 *
 * The timer-thread uses L4::Ipc_svr::Timeout_queue for keeping track of
 * callbacks and running them on time. Device models inherit from
 * L4::Ipc_svr::Timeout_queue::Timeout and implement their callbacks by
 * implementing the expired() method. The expired() method runs on the timer
 * thread, so the device model implementer needs to take care of mutual
 * exclusion to avoid race conditions. Also, only the requeue_timeout()
 * function may be used in the expired() method. enqueue_timeout() and
 * dequeue_timeout() make an IPC to the timer thread, which --if executed on
 * the timer thread-- will lock up Uvmm.
 *
 * Because the IPC framework does not handle interfaces, we encapsulate
 * timeouts in a struct and use that for communication with the timer thread.
 *
 * This infrastructure is used by timer device models such as the APIC timer,
 * the PIT and RTC.
 */

#pragma once

#include <vector>
#include <thread>
#include <pthread-l4.h>

#include <l4/sys/debugger.h>
#include <l4/sys/scheduler>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/object_registry>
#include <l4/sys/cxx/ipc_server_loop>
#include <l4/cxx/ipc_timeout_queue>
#include <l4/util/util.h>

#include "device.h"

namespace Vdev {

// Encapsulate Timeout_queue::Timeout pointers for IPC
struct Timeout_callback
{
  Timeout_callback()
  : timeout(nullptr)
  {}

  Timeout_callback(L4::Ipc_svr::Timeout_queue::Timeout *t)
  : timeout(t)
  {}

  L4::Ipc_svr::Timeout_queue::Timeout *timeout;
};

struct Clock_source_if : L4::Kobject_t<Clock_source_if, L4::Kobject, 0>
{
  L4_INLINE_RPC(long, add, (Timeout_callback cb, l4_kernel_clock_t timeout));
  L4_INLINE_RPC(long, remove, (Timeout_callback cb));
  typedef L4::Typeid::Rpcs<add_t, remove_t> Rpcs;
};

struct Clock_source_adapter
{
  virtual L4::Cap<Clock_source_if> ipc_if() = 0;
  virtual void requeue_timeout(L4::Ipc_svr::Timeout_queue::Timeout *t,
                               l4_kernel_clock_t timeout) = 0;
};

/**
 * Interface for the clock device models.
 */
class Timer : public virtual Vdev::Dev_ref
{
public:
  virtual ~Timer() = 0;
  virtual void tick() = 0;
  void set_clock_source(Clock_source_adapter *source)
  { _clock_source = source; }

protected:
  /**
   * Enqueue a timeout at the timeout queue. `timeout` must be in microseconds.
   * This must not be used from the timer thread.
   *
   */
  void enqueue_timeout(L4::Ipc_svr::Timeout_queue::Timeout *t,
                       l4_kernel_clock_t timeout)
  {
    _clock_source->ipc_if()->add(Timeout_callback(t), timeout);
  }

  /**
   * Remove a timeout from the timeout queue.
   * This must not be used from the timer thread.
   */
  void dequeue_timeout(L4::Ipc_svr::Timeout_queue::Timeout *t)
  {
    _clock_source->ipc_if()->remove(Timeout_callback(t));
  }

  /**
   * Re-queue a timeout.
   * This must only be called from the timer thread, e.g. from "expired()".
   */
  void requeue_timeout(L4::Ipc_svr::Timeout_queue::Timeout *t,
                       l4_kernel_clock_t timeout)
  {
    _clock_source->requeue_timeout(t, timeout);
  }

private:
  Clock_source_adapter *_clock_source;
};

inline Timer::~Timer() = default;

class Clock_source
: public L4::Epiface_t<Clock_source, Clock_source_if>,
  public Clock_source_adapter,
  public L4::Ipc_svr::Timeout_queue::Timeout
{
public:
  // Clock_source_if
  long op_add(Clock_source_if::Rights, Timeout_callback cb,
             l4_kernel_clock_t timeout)
  {
    assert(cb.timeout != nullptr);
    _server->remove_timeout(cb.timeout);
    _server->add_timeout(cb.timeout, timeout);
    return 0;
  }

  long op_remove(Clock_source_if::Rights, Timeout_callback cb)
  {
    assert(cb.timeout != nullptr);
    _server->remove_timeout(cb.timeout);
    return 0;
  }

  /**
   * Legacy interface:
   * periodically call tick() on all registered timers.
   */
  void expired()
  {
    for (auto t : _consumers)
      t->tick();

    // periodic invokation
    _server->add_timeout(this, timeout() + 27000);
  }

  // Register a Timer at this Clock source
  void add_timer(cxx::Ref_ptr<Timer> timer)
  { _consumers.push_back(timer); }

  /**
   * Migrate a vCPU's timer thread to its physical core and run the timer loop.
   *
   * The migration is needed so the timer value is consistent with the hardware
   * virtualized RDTSC instruction in the guest.
   *
   * \param vcpu_no      Guest vCPU number to run the timer for.
   * \param phys_cpu_id  Scheduler id of the physical core to run on.
   */
  void run_timer(unsigned vcpu_no, unsigned phys_cpu_id)
  {
    // raise timer thread prio above vcpu prio
    l4_sched_param_t sp = l4_sched_param(3);
    sp.affinity = l4_sched_cpu_set(phys_cpu_id, 0);
    auto sched = L4Re::Env::env()->scheduler();
    L4Re::chksys(sched->run_thread(Pthread::L4::cap(pthread_self()), sp),
                 "Run timer thread.");

    // instantiate server loop
    _server = new L4Re::Util::Registry_server<Loop_hooks>(
      Pthread::L4::cap(pthread_self()), L4Re::Env::env()->factory());
    _clock_if =
      L4::cap_cast<Clock_source_if>(_server->registry()->register_obj(this));

    Dbg().printf("Hello Timer on CPU %u\n", vcpu_no);
    char buf[18];
    snprintf(buf, sizeof(buf), "clock timer %1u", vcpu_no);
    l4_debugger_set_object_name(Pthread::L4::cap(pthread_self()).cap(), buf);

    // periodic timer (implements behaviour of the previous timer thread)
    _server->add_timeout(this, l4_kip_clock(l4re_kip()) + 27000);
    _server->loop();
  }

  /**
   * Start a new thread to run the timer loop.
   *
   * \param vcpu_no      Guest vCPU number to run the timer for.
   * \param phys_cpu_id  Scheduler id of the physical core to run on.
   */
  void start_timer_thread(unsigned vcpu_no, unsigned phys_cpu_id)
  {
    _thread = std::thread(&Clock_source::run_timer, this, vcpu_no, phys_cpu_id);

    for (auto timer : _consumers)
      timer->set_clock_source(this);
  }

  // Clock_source_adapter
  L4::Cap<Clock_source_if> ipc_if() override
  { return _clock_if; }

  void requeue_timeout(L4::Ipc_svr::Timeout_queue::Timeout *t,
                       l4_kernel_clock_t timeout) override
  {
    _server->remove_timeout(t);
    _server->add_timeout(t, timeout);
  }

private:
  class Loop_hooks
  : public L4::Ipc_svr::Timeout_queue_hooks<Loop_hooks>,
    public L4::Ipc_svr::Ignore_errors
  {
  public:
    /**
     * This function is required by Timeout_queue_hooks to get current time.
     */
    l4_kernel_clock_t now()
    { return l4_kip_clock(l4re_kip()); }
  };

  std::thread _thread;
  L4::Cap<Clock_source_if> _clock_if;
  std::vector<cxx::Ref_ptr<Timer>> _consumers;
  L4Re::Util::Registry_server<Loop_hooks> *_server;
};

} // namespace Vdev
