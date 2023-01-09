/*
 * Copyright (C) 2018-2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>

#include "device.h"

namespace Vmm {

/**
 * Interface for devices containing MSRs visible to the VM.
 */
struct Msr_device : virtual Vdev::Dev_ref
{
  virtual ~Msr_device() = 0;

  /**
   * Read from a MSR of the specified vCPU.
   *
   * \param msr         Number of the MSR to read.
   * \param value[out]  Pointer to the memory to read into.
   * \param vcpu_no     Number of the vCPU to read from.
   *
   * The vCPU number passed is of an existing vCPU.
   */
  virtual bool read_msr(unsigned msr, l4_uint64_t *value,
                        unsigned vcpu_no) const = 0;
  /**
   * Write to a MSR of the specificed vCPU.
   *
   * \param msr      Number of the MSR to write to.
   * \param value    Value to write to the MSR.
   * \param vcpu_no  Number of the vCPU to write to.
   *
   * The vCPU number passed is of an existing vCPU.
   */
  virtual bool write_msr(unsigned msr, l4_uint64_t value, unsigned vcpu_no) = 0;
};

inline Msr_device::~Msr_device() = default;

} // namespace
