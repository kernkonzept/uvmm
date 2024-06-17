/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cassert>
#include <cstdio>

#include <l4/sys/consts.h>
#include <l4/sys/l4int.h>

#include "cpu_dev.h"
#include "device.h"
#include "pt_walker.h"
#include "vcpu_ptr.h"
#include "debugger/generic_guest_debugger.h"
#include "monitor/mem_dump.h"

namespace Monitor {

void
Generic_guest_debugger::dump_memory(FILE *f,
                                    Mem_dumper *mem_dumper,
                                    Vmm::Vcpu_ptr vcpu)
{
  l4_addr_t gvirt_start = mem_dumper->addr_start();
  l4_addr_t gvirt_end = mem_dumper->addr_end();

  l4_addr_t hvirt_start = walk_page_table(gvirt_start, vcpu);

  mem_dumper->dump(f, hvirt_start, l4_round_page(gvirt_end) - gvirt_start);
}

Vmm::Vcpu_ptr
Generic_guest_debugger::vcpu_ptr(unsigned vcpu) const
{ return vcpu_valid(vcpu) ? _devs->cpus()->vcpu(vcpu) : Vmm::Vcpu_ptr(nullptr); }

bool
Generic_guest_debugger::vcpu_valid(unsigned vcpu) const
{ return vcpu < _devs->cpus()->size() && _devs->cpus()->vcpu_exists(vcpu); }

bool
Generic_guest_debugger::vcpu_smp_active() const
{ return _devs->cpus()->max_cpuid() > 0; }

l4_addr_t
Generic_guest_debugger::walk_page_table(l4_addr_t gvirt, Vmm::Vcpu_ptr vcpu)
{ return vcpu.get_pt_walker()->walk(vcpu.vm_state()->cr3(), gvirt); }

}
