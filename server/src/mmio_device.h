/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/sys/task>
#include <l4/sys/l4int.h>
#include <l4/sys/types.h>

#include "device.h"
#include "vcpu.h"

namespace Vmm {

struct Mmio_device : public virtual Vdev::Dev_ref
{
  virtual ~Mmio_device() = 0;

  virtual bool access(l4_addr_t pfa, l4_addr_t offset, Cpu vcpu,
                      L4::Cap<L4::Task> vm_task, l4_addr_t s, l4_addr_t e) = 0;
};

inline Mmio_device::~Mmio_device() = default;

}
