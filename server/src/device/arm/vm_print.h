/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2019-2020 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 */
#pragma once

#include <vector>

#include "smccc_device.h"
#include "vmprint.h"

namespace {

static Dbg warn(Dbg::Dev, Dbg::Warn, "vm_print");
static Dbg info(Dbg::Dev, Dbg::Info, "vm_print");

class Vm_print_device : public Vdev::Device, public Vmm::Smccc_device
{
  enum Vm_print_error_codes
  {
    Success = 0,
  };

public:
  explicit Vm_print_device(unsigned max_cpus)
  : _guest_print(max_cpus)
  {}

  bool vm_call(unsigned imm, Vmm::Vcpu_ptr vcpu) override
  {
    if (imm != 1)
      return false;

    if (!is_valid_func_id(vcpu->r.r[0]))
      return false;

    assert(vmm_current_cpu_id < _guest_print.size());

    _guest_print[vmm_current_cpu_id].print_char(vcpu->r.r[1]);
    vcpu->r.r[0] = Success;

    return true;
  }

private:
  bool is_valid_func_id(l4_umword_t reg) const
  {
    // Check for the correct SMC calling convention:
    // - this must be a fast call (bit 31)
    // - it is within the uvmm range (bits 29:24)
    // - the rest must be zero
    return (reg & 0xbfffffff) == 0x86000000;
  }

  std::vector<Vmm::Guest_print_buffer> _guest_print;
};

}
