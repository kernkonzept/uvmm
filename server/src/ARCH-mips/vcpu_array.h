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

namespace Vmm {

/**
 * MIPS virtual CPU device.
 */
class Vcpu_dev : public Vdev::Device
{
public:
  enum { Default_procid = 0x00010000 };

  Vcpu_dev(unsigned id, l4_addr_t vcpu_baseaddr)
  : _vcpu(Cpu((l4_vcpu_state_t *) vcpu_baseaddr))
  {
    _vcpu.set_vcpu_id(id);
    _vcpu.set_proc_id(Default_procid);
    _vcpu.alloc_fpu_state();
  }

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &,
                   Vmm::Guest *, Vmm::Virt_bus *) override
  {}

  void set_proc_type(char const *compatible);

  Cpu vcpu() const
  { return _vcpu; }

private:
  Cpu _vcpu;
};

/**
 * MIPS CPU array.
 */
class Vcpu_array : public Vcpu_array_t<Vcpu_dev, 32>
{
public:
  void show_state_registers(FILE *f);
};

} // namespace
