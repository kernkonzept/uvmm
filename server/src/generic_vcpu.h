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
#include <l4/re/util/kumem_alloc>
#include <l4/sys/debugger.h>
#include <l4/sys/thread>
#include <l4/sys/vcpu.h>

#include "debug.h"

namespace Vmm {

/**
 * Describes a load/store instruction.
 */
struct Mem_access
{
  enum Kind
  {
    Load,  /// load from memory
    Store, /// store to memory
    Other  /// unknown instruction
  };

  enum Width
  {
    Wd8 = 0,  // Byte access
    Wd16 = 1, // Half-word access
    Wd32 = 2, // Word access
    Wd64 = 3, // Double word access
  };

  l4_uint64_t value;
  Kind access;
  char width;
};

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

    char threadname[8];
    snprintf(threadname, 8, "vcpu%d", get_vcpu_id());
    threadname[7] = '\0';
    l4_debugger_set_object_name(thread.cap(), threadname);

    auto ipi = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Irq>(),
                            "allocate vcpu notification interrupt");
    L4Re::Env::env()->factory()->create(ipi);
    ipi->attach(0, thread);

    _s->user_data[Reg_ipi_irq] = ipi.cap();

    trace().printf("VCPU mapped @ %p and enabled\n", _s);
  }

  unsigned get_vcpu_id() const
  { return _s->user_data[Reg_vcpu_id]; }

  void set_vcpu_id(unsigned id)
  { _s->user_data[Reg_vcpu_id] = id; }

  void ping()
  { L4::Cap<L4::Irq>(_s->user_data[Reg_ipi_irq])->trigger(); }

protected:
  enum User_data_regs
  {
    Reg_vcpu_id = 0,
    Reg_ipi_irq,
    Reg_arch_base
  };

  static Dbg warn()
  { return Dbg(Dbg::Cpu, Dbg::Warn); }

  static Dbg info()
  { return Dbg(Dbg::Cpu, Dbg::Info); }

  static Dbg trace()
  { return Dbg(Dbg::Cpu, Dbg::Trace); }

  static_assert(Reg_arch_base <= 7, "Too many user_data registers used");

  explicit Generic_cpu(l4_vcpu_state_t *s) : _s(s) {}

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
