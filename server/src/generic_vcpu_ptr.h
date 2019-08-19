/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include <l4/re/error_helper>
#include <l4/re/rm>
#include <l4/re/util/cap_alloc>
#include <l4/sys/thread>
#include <l4/sys/vcpu.h>

#include "debug.h"

namespace Vmm {

class Pt_walker;

class Generic_vcpu_ptr
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

    if (!l4_vcpu_check_version(_s))
      {
        Err().printf("FATAL: Could not create vCPU. "
                     "vCPU interface mismatch - Kernel %lx != User %x.\n",
                     _s->version, L4_VCPU_STATE_VERSION);
        L4Re::chksys(-L4_ENODEV);
      }

    trace().printf("VCPU mapped @ %p and enabled\n", _s);
  }

  unsigned get_vcpu_id() const
  { return _s->user_data[Reg_vcpu_id]; }

  void set_vcpu_id(unsigned id)
  { _s->user_data[Reg_vcpu_id] = id; }

  Pt_walker *get_pt_walker() const
  { return reinterpret_cast<Pt_walker *>(_s->user_data[Reg_ptw_ptr]); }

  void set_pt_walker(Pt_walker *ptw)
  { _s->user_data[Reg_ptw_ptr] = reinterpret_cast<l4_umword_t>(ptw); }

protected:
  enum User_data_regs
  {
    Reg_vcpu_id = 0,
    Reg_ptw_ptr,
    Reg_arch_base
  };

  static Dbg warn()
  { return Dbg(Dbg::Cpu, Dbg::Warn); }

  static Dbg info()
  { return Dbg(Dbg::Cpu, Dbg::Info); }

  static Dbg trace()
  { return Dbg(Dbg::Cpu, Dbg::Trace); }

  static_assert(Reg_arch_base <= 7, "Too many user_data registers used");

  explicit Generic_vcpu_ptr(l4_vcpu_state_t *s) : _s(s) {}

  static l4_umword_t reg_extend_width(l4_umword_t value, char size, bool signext)
  {
    if (signext)
      {
        switch (size)
          {
          case 0: return (l4_mword_t)((l4_int8_t)value);
          case 1: return (l4_mword_t)((l4_int16_t)value);
          case 2: return (l4_mword_t)((l4_int32_t)value);
          default: return value;
          }
      }

    switch (size)
      {
      case 0: return (l4_umword_t)((l4_uint8_t)value);
      case 1: return (l4_umword_t)((l4_uint16_t)value);
      case 2: return (l4_umword_t)((l4_uint32_t)value);
      default: return value;
      }
  }

  l4_vcpu_state_t *_s;
};

}
