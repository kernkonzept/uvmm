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
#include <l4/re/util/kumem_alloc>

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
    l4_addr_t vcpu_addr;

    L4Re::chksys(L4Re::Util::kumem_alloc(&vcpu_addr, 0),
                 "kumem alloc for vCPU");

    Dbg(Dbg::Cpu, Dbg::Info).printf("Created VCPU %u @ %lx\n", idx, vcpu_addr);

    _vcpu = Vcpu_ptr((l4_vcpu_state_t *)vcpu_addr);
    _vcpu.set_vcpu_id(idx);

    // entry_sp signals the state the CPU is in. When it starts for the very
    // first time, entry_sp is zero and needs to be initialised based on the
    // currently used stack. When the CPU is switched off and on again the
    // stack is re-used as is.
    _vcpu->entry_sp = 0;
  }

  Vcpu_ptr vcpu() const
  { return _vcpu; }

  void powerup_cpu();
  void reschedule();

  virtual void reset() = 0;

  /**
   * Start CPU, run through reset and resume to the VM.
   */
  void startup();

  L4::Cap<L4::Thread> thread_cap() const
  { return Pthread::L4::cap(_thread); }

protected:
  Vcpu_ptr _vcpu;
  /// physical CPU to run on (offset into scheduling mask)
  unsigned _phys_cpu_id;
  pthread_t _thread;
};


}
