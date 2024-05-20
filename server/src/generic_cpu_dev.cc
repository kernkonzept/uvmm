/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "generic_cpu_dev.h"

#include <cstdio>

#include <l4/sys/debugger.h>
#include <l4/sys/scheduler>

namespace Vmm {

Vcpu_ptr Generic_cpu_dev::_main_vcpu(nullptr);
L4Re::Util::Br_manager Generic_cpu_dev::_main_bm;
Vcpu_obj_registry Generic_cpu_dev::_main_registry(&Generic_cpu_dev::_main_bm);
bool Generic_cpu_dev::_main_vcpu_used = false;

void
Generic_cpu_dev::startup()
{
  // CPU 0 is the boot CPU and the main thread is already attached
  if (!_attached)
    {
      _attached = true;
      _vcpu.thread_attach();
    }

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
          return static_cast<void *>(nullptr);
        }, this);

      if (L4_UNLIKELY(pthread_attr_destroy(&pattr)))
        L4Re::chksys(-L4_ENOMEM, "Destroying pthread attributes.");

      if (err != 0)
        L4Re::chksys(-L4_EAGAIN, "Cannot start vcpu thread");

      _registry.set_server(thread_cap());
      _vcpu.set_ipc_registry(&_registry);
      _vcpu.set_bm(&_bm);
    }

  char n[8];
  snprintf(n, sizeof(n), "vcpu%d", id);
  l4_debugger_set_object_name(pthread_l4_cap(_thread), n);
}

void
Generic_cpu_dev::reschedule()
{
  Dbg(Dbg::Cpu, Dbg::Info)
    .printf("reschedule(): Initiating cpu startup for cap 0x%lx/core %u\n",
            Pthread::L4::cap(_thread).cap(), _vcpu.get_vcpu_id());

  l4_sched_param_t sp = l4_sched_param(2);
  sp.affinity = l4_sched_cpu_set(_phys_cpu_id, 0);

  auto sched = L4Re::Env::env()->scheduler();
  L4Re::chksys(sched->run_thread(Pthread::L4::cap(_thread), sp),
               "Schedule vCPU on new core.");
}

}
