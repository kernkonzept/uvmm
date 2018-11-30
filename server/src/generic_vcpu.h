/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/error_helper>
#include <l4/re/rm>
#include <l4/re/util/kumem_alloc>
#include <l4/sys/thread>
#include <l4/sys/vcpu.h>

#include "debug.h"

namespace Vmm {

class Generic_cpu
{
public:
  l4_vcpu_state_t *operator -> () const noexcept
  { return _s; }

  l4_vcpu_state_t *operator * () const noexcept
  { return _s; }

  void control_ext(L4::Cap<L4::Thread> thread)
  {
    if (l4_error(thread->vcpu_control_ext((l4_addr_t)_s)))
    {
      Err().printf("FATAL: Could not create vCPU. "
                   "Running virtualization-enabled kernel?\n");
      L4Re::chksys(-L4_ENODEV);
    }

    Dbg(Dbg::Info).printf("VCPU mapped @ %p and enabled\n", _s);
  }

protected:
  explicit Generic_cpu(l4_vcpu_state_t *s) : _s(s) {}

  l4_vcpu_state_t *_s;
};

}
