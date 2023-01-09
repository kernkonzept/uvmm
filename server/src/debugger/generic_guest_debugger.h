/*
 * Copyright (C) 2019, 2023 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include <l4/sys/l4int.h>

#include "vcpu_ptr.h"
#include "vm.h"

namespace Vdev {
  struct Device_lookup;
}

namespace Monitor {

class Mem_dumper;

class Generic_guest_debugger
{
public:
  Generic_guest_debugger(Vmm::Vm *vm)
  : _devs(vm)
  {}

  virtual ~Generic_guest_debugger() = default;

  // memory dumping
  void dump_memory(FILE *f, Mem_dumper *mem_dumper, Vmm::Vcpu_ptr vcpu);

  // convenience methods
  Vmm::Vcpu_ptr vcpu_ptr(unsigned vcpu) const;
  bool vcpu_valid(unsigned vcpu) const;
  bool vcpu_smp_active() const;

private:
  l4_addr_t walk_page_table(l4_addr_t gvirt, Vmm::Vcpu_ptr vcpu);

  Vdev::Device_lookup *_devs;
};

}
