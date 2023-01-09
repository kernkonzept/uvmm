/*
 * Copyright (C) 2019-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "msr_device.h"
#include "vcpu_ptr.h"

namespace Vdev {

/**
 * MSR device handling read access to IA32_BIOS_SIGN_ID.
 *
 * This MSR provides the currently loaded microcode revision in bit [32:63].
 * As MSR access is a priviledged instruction this data can only be read with
 * support from the kernel. By default, the kernel provides the relevant 32
 * bits of IA32_BIOS_SIGN_ID in the last user_data register of the vCPU state.
 */
class Microcode_revision : public Vmm::Msr_device
{
  enum { Ia32_bios_sign_id = 0x8b };

public:
  Microcode_revision(Vmm::Vcpu_ptr vcpu)
  : _ucode_revision((l4_uint64_t)vcpu.ucode_revision() << 32)
  {
    // Fiasco reports just the upper 32-bit aka microcode revision. To recreate
    // the complete MSR, we need to shift it to the upper 32-bit of the 64-bit
    // MSR.
  }

  bool read_msr(unsigned msr, l4_uint64_t *value, unsigned) const override
  {
    if (msr != Ia32_bios_sign_id)
      return false;

    *value = _ucode_revision;
    return true;
  }

  bool write_msr(unsigned, l4_uint64_t, unsigned) override
  { return false; }

private:
  l4_uint64_t const _ucode_revision;
}; // Microcode_revision

} // namespace Vdev
