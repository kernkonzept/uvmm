/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "generic_cpu_dev.h"

#include <cstdio>
#include <cstring>

#include <l4/sys/debugger.h>
#include <l4/sys/scheduler>

namespace Vmm {

void
Generic_cpu_dev::startup()
{
  _vcpu.thread_attach();
  reset();
}

void
Generic_cpu_dev::powerup_cpu()
{
  unsigned id = _vcpu.get_vcpu_id();

  if (id == 0)
    {
      _thread = pthread_self();
      reschedule();
    }
  else
    {
      int err;
      pthread_attr_t pattr;
      err = pthread_attr_init(&pattr);
      if (L4_UNLIKELY(err))
        L4Re::chksys(-L4_ENOMEM, "Initializing pthread attributes.");

      pattr.create_flags |= PTHREAD_L4_ATTR_NO_START;
      err = pthread_create(&_thread, &pattr, [](void *cpu) {
          reinterpret_cast<Generic_cpu_dev *>(cpu)->startup();
          return (void *)nullptr;
        }, this);

      if (err != 0)
        L4Re::chksys(-L4_EAGAIN, "Cannot start vcpu thread");

      err = pthread_attr_destroy(&pattr);
      if (L4_UNLIKELY(err))
        L4Re::chksys(-L4_ENOMEM, "Destroying pthread attributes.");
    }

  char n[8];
  snprintf(n, sizeof(n), "vcpu%d", id);
  l4_debugger_set_object_name(pthread_l4_cap(_thread), n);
}

void
Generic_cpu_dev::reschedule()
{
  l4_sched_param_t sp = l4_sched_param(2);
  sp.affinity = l4_sched_cpu_set(_phys_cpu_id, 0);

  auto sched = L4Re::Env::env()->scheduler();
  L4Re::chksys(sched->run_thread(Pthread::L4::cap(_thread), sp));
}

}
