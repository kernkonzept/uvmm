/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include "vcpu_array_t.h"

namespace Vmm
{

/**
 * ARM virtual CPU device.
 */
class Vcpu_dev : public Vdev::Device
{
public:
  Vcpu_dev(unsigned id, l4_addr_t vcpu_baseaddr, unsigned phys_id)
  : _vcpu(Cpu((l4_vcpu_state_t *)vcpu_baseaddr)), _phys_cpu_id(phys_id)
  {
    _vcpu.set_vcpu_id(id);
  }

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &,
                   Vmm::Guest *, Vmm::Virt_bus *) override
  {}

  void set_proc_type(char const *) {}

  Cpu vcpu() const { return _vcpu; }

  unsigned sched_cpu() const
  { return _phys_cpu_id; }

private:
  Cpu _vcpu;
  /// physical CPU to run on (offset into scheduling mask)
  unsigned _phys_cpu_id;
};

class Vcpu_array : public Vcpu_array_t<Vcpu_dev, 32>
{
public:
  void show_state_registers(FILE *f);
};

} // namespace
