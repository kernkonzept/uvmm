/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Jakub Jermar <jakub.jermar@kernkonzept.com>
 */
#pragma once

#include <l4/sys/types.h>

#include "device.h"

namespace Vmm {

/**
 * Interface for devices responding to guest CPUID invocations.
 */
struct Cpuid_device : virtual Vdev::Dev_ref
{
  virtual ~Cpuid_device() = 0;

  /**
   * Handle the CPUID instruction.
   *
   * \param regs        Guest register state.
   * \param a[out]      Output value for RAX.
   * \param b[out]      Output value for RBX.
   * \param c[out]      Output value for RCX.
   * \param d[out]      Output value for RDX.
   *
   * \return             True if the device handled the CPUID instruction,
   *                     false otherwise.
   */
  virtual bool handle_cpuid(l4_vcpu_regs_t const *regs, unsigned *a,
                            unsigned *b, unsigned *c, unsigned *d) const = 0;
};

inline Cpuid_device::~Cpuid_device() = default;

} // namespace
