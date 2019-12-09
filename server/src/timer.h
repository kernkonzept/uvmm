/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <vector>
#include <thread>
#include <pthread-l4.h>

#include <l4/sys/debugger.h>
#include <l4/sys/scheduler>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/util/util.h>

#include "device.h"

namespace Vdev {

struct Timer : virtual Vdev::Dev_ref
{
  virtual ~Timer() = 0;
  virtual void tick() = 0;
};

inline Timer::~Timer() = default;

class Clock_source
{
public:
  void add_timer(cxx::Ref_ptr<Timer> timer)
  {
    _consumers.push_back(timer);
  }

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
    l4_sched_param_t sp = l4_sched_param(2);
    sp.affinity = l4_sched_cpu_set(phys_cpu_id, 0);
    auto sched = L4Re::Env::env()->scheduler();
    L4Re::chksys(sched->run_thread(Pthread::L4::cap(pthread_self()), sp));

    Dbg().printf("Hello Timer on CPU %u\n", vcpu_no);
    char buf[18];
    snprintf(buf, sizeof(buf), "clock timer %1u", vcpu_no);
    l4_debugger_set_object_name(Pthread::L4::cap(pthread_self()).cap(), buf);

    // now loop forever
    while(1)
      {
        l4_sleep(27);

        for (auto t : _consumers)
          t->tick();
      }
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
  }

private:
  std::thread _thread;
  std::vector<cxx::Ref_ptr<Timer>> _consumers;
};

} // namespace Vdev
