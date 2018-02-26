/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "device.h"
#include "vcpu_ptr.h"

namespace Vmm {

struct Smc_device : public virtual Vdev::Dev_ref
{
  virtual ~Smc_device() = 0;

  virtual void smc(Vcpu_ptr vcpu) = 0;
};

inline Smc_device::~Smc_device() = default;

}
