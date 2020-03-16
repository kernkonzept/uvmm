/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
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
private:
  static Vcpu_ptr alloc_vcpu(unsigned idx)
  {
    l4_addr_t vcpu_addr;

    L4Re::chksys(L4Re::Util::kumem_alloc(&vcpu_addr, 0),
                 "kumem alloc for vCPU");

    Dbg(Dbg::Cpu, Dbg::Info).printf("Created VCPU %u @ %lx\n", idx, vcpu_addr);

    return Vcpu_ptr((l4_vcpu_state_t *)vcpu_addr);
  }

public:
  Generic_cpu_dev(unsigned idx, unsigned phys_id)
  : _vcpu(nullptr), _phys_cpu_id(phys_id)
  {
    // The CPU 0 (boot CPU) vCPU is allocated in main
    if (_main_vcpu_used || (idx != 0))
      _vcpu = alloc_vcpu(idx);
    else
      {
        _attached = true;
        _vcpu = _main_vcpu;
        _main_vcpu_used = true;
      }

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

  static Vcpu_ptr main_vcpu() { return _main_vcpu; }

  static void alloc_main_vcpu()
  {
    if (*_main_vcpu)
      L4Re::throw_error(-L4_EEXIST, "cannot allocate mutiple main CPUs");

    _main_vcpu = alloc_vcpu(0);
    _main_vcpu.thread_attach();
  }

protected:
  Vcpu_ptr _vcpu;
  /// physical CPU to run on (offset into scheduling mask)
  unsigned _phys_cpu_id;
  pthread_t _thread;
  bool _attached = false;

private:
  static Vcpu_ptr _main_vcpu;
  static bool _main_vcpu_used;
};


}
