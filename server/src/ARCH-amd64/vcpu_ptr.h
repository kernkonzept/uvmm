/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "generic_vcpu_ptr.h"
#include "mem_access.h"
#include "vm_state.h"

#include <string>
#include <assert.h>

namespace Vmm {

class Pt_walker;

class Vcpu_ptr : public Generic_vcpu_ptr
{
public:
  enum User_data_regs_arch
  {
    Reg_vmm_type = Reg_arch_base,
    Reg_ptw_ptr,
    Reg_mmio_read,
  };
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

  void reset()
  {
    // VMX/SVM specific stuff done in setup_protected_mode
    vm_state()->init_state();
    vm_state()->setup_protected_mode(_s->r.ip);
  }

  void register_pt_walker(Pt_walker const *ptw)
  {
    _s->user_data[Reg_ptw_ptr] = reinterpret_cast<l4_umword_t>(ptw);
  }

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

