/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#pragma once

#include <pthread.h>
#include <pthread-l4.h>

#include <l4/re/error_helper>
#include <l4/re/env>
#include <l4/re/rm>
#include <l4/sys/task>

#include <debug.h>
#include <device.h>
#include <vcpu_ptr.h>

namespace Vmm {

class Generic_cpu_dev : public Vdev::Device
{
public:
  Generic_cpu_dev(unsigned idx, unsigned phys_id)
  : _vcpu(nullptr), _phys_cpu_id(phys_id)
  {
    auto *e = L4Re::Env::env();
    l4_addr_t vcpu_addr = 0x10000000;

    L4Re::chksys(e->rm()->reserve_area(&vcpu_addr, L4_PAGESIZE,
                                       L4Re::Rm::Search_addr));
    L4Re::chksys(e->task()->add_ku_mem(
                   l4_fpage(vcpu_addr, L4_PAGESHIFT, L4_FPAGE_RW)),
                 "kumem alloc for vCPU");

    Dbg(Dbg::Cpu, Dbg::Info).printf("Created VCPU %u @ %lx\n", idx, vcpu_addr);

    _vcpu = Vcpu_ptr((l4_vcpu_state_t *)vcpu_addr);
    _vcpu.set_vcpu_id(idx);
  }

  Vcpu_ptr vcpu() const
  { return _vcpu; }

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override
  {}

  void powerup_cpu();
  void reschedule();

  virtual void reset() = 0;

  /**
   * Start CPU, run through reset and resume to the VM.
   */
  void startup();

  L4::Cap<L4::Thread> thread_cap() const
  { return L4::Cap<L4::Thread>(pthread_l4_cap(_thread)); }

protected:
  Vcpu_ptr _vcpu;
  /// physical CPU to run on (offset into scheduling mask)
  unsigned _phys_cpu_id;
  pthread_t _thread;
};


}
