/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "generic_cpu.h"

#include <pthread.h>
#include <pthread-l4.h>

#include <cstring>

#include <l4/sys/debugger.h>
#include <l4/sys/scheduler>

namespace Vmm {

void
Generic_cpu_dev::startup(bool boot_to_halt)
{
  auto utcb = l4_utcb();

  _vcpu.thread_attach();

  _running = !boot_to_halt;

  while (!_running)
    {
      l4_umword_t label;
      l4_ipc_wait(utcb, &label, L4_IPC_NEVER);
    }

  reset();
}

void
Generic_cpu_dev::powerup_cpu()
{
  unsigned id = _vcpu.get_vcpu_id();
  pthread_t thread;

  if (id == 0)
    thread = pthread_self();
  else
    {
      pthread_attr_t pattr;
      L4Re::chksys(pthread_attr_init(&pattr));
      pattr.create_flags |= PTHREAD_L4_ATTR_NO_START;
      auto r = pthread_create(&thread, &pattr, [](void *cpu) {
          reinterpret_cast<Generic_cpu_dev *>(cpu)->startup(true);
          return (void *)nullptr;
        }, this);

      if (r != 0)
        L4Re::chksys(-r, "Cannot start vcpu thread");

      L4Re::chksys(pthread_attr_destroy(&pattr));
    }

  if (id < 100)
    {
      char vcpu_name[7];
      sprintf(vcpu_name, "vcpu%02d", id);
      l4_debugger_set_object_name(pthread_l4_cap(thread), vcpu_name);
    }

  l4_sched_param_t sp = l4_sched_param(2);
  sp.affinity = l4_sched_cpu_set(sched_cpu(), 0);

  auto sched = L4Re::Env::env()->scheduler();
  L4Re::chksys(sched->run_thread(Pthread::L4::cap(thread), sp));
}

}
