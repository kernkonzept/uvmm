/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 */
#pragma once

#include "device.h"
#include "vcpu_ptr.h"

namespace Vmm {

/**
 * Base class for all devices implementing the SMC calling convention.
 */
struct Smccc_device : public virtual Vdev::Dev_ref
{
  enum
  {
    Not_supported = -1
  };

  virtual ~Smccc_device() = 0;

  /**
   * Method called by the vmm on either a SMC/HVC call.
   *
   * \param imm   Immediate value of the SMC/HVC instruction.
   * \param vcpu  The cpu pointer when trapped. vcpu->r.ip points to the
   *              instruction after the trapped SMC/HVC instruction
   *
   * \return  True when the call was handled by the implementation and false
   *          otherwise.
   */
  virtual bool vm_call(unsigned imm, Vcpu_ptr vcpu) = 0;

  static constexpr bool is_64bit_call(l4_umword_t reg)
  {
    // Bit 30 must be set for 64 bit calls
    return reg & (1 << 30);
  }

  static constexpr bool is_fast_call(l4_umword_t reg)
  {
    // Bit 31 must be set for fastcalls
    return reg & (1 << 31);
  }

  static constexpr bool is_valid_call(l4_umword_t reg)
  {
    // Check for SMC calling convention bitness:
    // 64 bit SMCCC is only allowed on a 64 bit host
    return !(is_64bit_call(reg) && sizeof(long) == 4);
  }
};

inline Smccc_device::~Smccc_device() = default;

}
