/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include "generic_vcpu_ptr.h"
#include "mem_access.h"
#include "vm_state.h"

namespace Vmm {

class Pt_walker;

class Vcpu_ptr : public Generic_vcpu_ptr
{
public:
  enum User_data_regs_arch
  {
    Reg_vmm_type = Reg_arch_base,
    Reg_mmio_read,
    // <insert further register usage here>
    Reg_must_be_last_before_ucode,
    Reg_ucode_rev = 6, // must be in sync with Fiasco
  };
  static_assert(Reg_ucode_rev >= Reg_must_be_last_before_ucode,
                "Last user data register is reserved for microcode revision.");

  enum class Vm_state_t { Vmx, Svm };

  explicit Vcpu_ptr(l4_vcpu_state_t *s) : Generic_vcpu_ptr(s)
  {
    if (s)
      create_state(determine_vmm_type());
  }

  bool pf_write() const
  {
    return vm_state()->pf_write();
  }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
  }

  Vm_state *vm_state() const
  { return reinterpret_cast<Vm_state *>(_s->user_data[Reg_vmm_type]);}

  Mem_access decode_mmio() const;

  void writeback_mmio(Mem_access const m)
  {
    // used to write read value back to register it is read to.
    *decode_reg_ptr(_s->user_data[Reg_mmio_read]) = m.value;
  }

  void reset();

  l4_umword_t ucode_revision() const
  { return _s->user_data[Reg_ucode_rev]; }

private:
  void *extended_state() const
  {
    return (void *)(((char *)_s) + L4_VCPU_OFFSET_EXT_STATE);
  }

  Vm_state_t determine_vmm_type();
  void create_state(Vm_state_t type);
  l4_umword_t *decode_reg_ptr(int value) const;

}; // class Vcpu_ptr

} // namespace Vmm

