/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/static_container>

#include "guest.h"
#include "guest_entry.h"
#include "vcpu_ptr.h"

/// The singleton instance of the VMM.
static cxx::Static_container<Vmm::Guest> guest;

static void
save_fpu(Vmm::Fpu_state *s)
{
  asm volatile(".set   push\n");
  asm volatile(".set   hardfloat\n");
#if __mips_fpr == 64
  asm volatile("sdc1 $f0, %0" : : "m"(s->regs[0]));
  asm volatile("sdc1 $f1, %0" : : "m"(s->regs[1]));
  asm volatile("sdc1 $f2, %0" : : "m"(s->regs[2]));
  asm volatile("sdc1 $f3, %0" : : "m"(s->regs[3]));
  asm volatile("sdc1 $f4, %0" : : "m"(s->regs[4]));
  asm volatile("sdc1 $f5, %0" : : "m"(s->regs[5]));
  asm volatile("sdc1 $f6, %0" : : "m"(s->regs[6]));
  asm volatile("sdc1 $f7, %0" : : "m"(s->regs[7]));
  asm volatile("sdc1 $f8, %0" : : "m"(s->regs[8]));
  asm volatile("sdc1 $f9, %0" : : "m"(s->regs[9]));
  asm volatile("sdc1 $f10, %0" : : "m"(s->regs[10]));
  asm volatile("sdc1 $f11, %0" : : "m"(s->regs[11]));
  asm volatile("sdc1 $f12, %0" : : "m"(s->regs[12]));
  asm volatile("sdc1 $f13, %0" : : "m"(s->regs[13]));
  asm volatile("sdc1 $f14, %0" : : "m"(s->regs[14]));
  asm volatile("sdc1 $f15, %0" : : "m"(s->regs[15]));
  asm volatile("sdc1 $f16, %0" : : "m"(s->regs[16]));
  asm volatile("sdc1 $f17, %0" : : "m"(s->regs[17]));
  asm volatile("sdc1 $f18, %0" : : "m"(s->regs[18]));
  asm volatile("sdc1 $f19, %0" : : "m"(s->regs[19]));
  asm volatile("sdc1 $f20, %0" : : "m"(s->regs[20]));
  asm volatile("sdc1 $f21, %0" : : "m"(s->regs[21]));
  asm volatile("sdc1 $f22, %0" : : "m"(s->regs[22]));
  asm volatile("sdc1 $f23, %0" : : "m"(s->regs[23]));
  asm volatile("sdc1 $f24, %0" : : "m"(s->regs[24]));
  asm volatile("sdc1 $f25, %0" : : "m"(s->regs[25]));
  asm volatile("sdc1 $f26, %0" : : "m"(s->regs[26]));
  asm volatile("sdc1 $f27, %0" : : "m"(s->regs[27]));
  asm volatile("sdc1 $f28, %0" : : "m"(s->regs[28]));
  asm volatile("sdc1 $f29, %0" : : "m"(s->regs[29]));
  asm volatile("sdc1 $f30, %0" : : "m"(s->regs[30]));
  asm volatile("sdc1 $f31, %0" : : "m"(s->regs[31]));
#else
  asm volatile("sdc1 $f0, %0" : : "m"(s->regs[0]));
  asm volatile("sdc1 $f2, %0" : : "m"(s->regs[1]));
  asm volatile("sdc1 $f4, %0" : : "m"(s->regs[2]));
  asm volatile("sdc1 $f6, %0" : : "m"(s->regs[3]));
  asm volatile("sdc1 $f8, %0" : : "m"(s->regs[4]));
  asm volatile("sdc1 $f10, %0" : : "m"(s->regs[5]));
  asm volatile("sdc1 $f12, %0" : : "m"(s->regs[6]));
  asm volatile("sdc1 $f14, %0" : : "m"(s->regs[7]));
  asm volatile("sdc1 $f16, %0" : : "m"(s->regs[8]));
  asm volatile("sdc1 $f18, %0" : : "m"(s->regs[9]));
  asm volatile("sdc1 $f20, %0" : : "m"(s->regs[10]));
  asm volatile("sdc1 $f22, %0" : : "m"(s->regs[11]));
  asm volatile("sdc1 $f24, %0" : : "m"(s->regs[12]));
  asm volatile("sdc1 $f26, %0" : : "m"(s->regs[13]));
  asm volatile("sdc1 $f28, %0" : : "m"(s->regs[14]));
  asm volatile("sdc1 $f30, %0" : : "m"(s->regs[15]));
#endif
  asm volatile("cfc1 %0, $31" : "=r"(s->status));
  asm volatile(".set   pop\n");
}

static void
restore_fpu(Vmm::Fpu_state const *s)
{
  asm volatile(".set   push\n");
  asm volatile(".set   hardfloat\n");
#if __mips_fpr == 64
  asm volatile("ldc1 $f0, %0" : : "m"(s->regs[0]));
  asm volatile("ldc1 $f1, %0" : : "m"(s->regs[1]));
  asm volatile("ldc1 $f2, %0" : : "m"(s->regs[2]));
  asm volatile("ldc1 $f3, %0" : : "m"(s->regs[3]));
  asm volatile("ldc1 $f4, %0" : : "m"(s->regs[4]));
  asm volatile("ldc1 $f5, %0" : : "m"(s->regs[5]));
  asm volatile("ldc1 $f6, %0" : : "m"(s->regs[6]));
  asm volatile("ldc1 $f7, %0" : : "m"(s->regs[7]));
  asm volatile("ldc1 $f8, %0" : : "m"(s->regs[8]));
  asm volatile("ldc1 $f9, %0" : : "m"(s->regs[9]));
  asm volatile("ldc1 $f10, %0" : : "m"(s->regs[10]));
  asm volatile("ldc1 $f11, %0" : : "m"(s->regs[11]));
  asm volatile("ldc1 $f12, %0" : : "m"(s->regs[12]));
  asm volatile("ldc1 $f13, %0" : : "m"(s->regs[13]));
  asm volatile("ldc1 $f14, %0" : : "m"(s->regs[14]));
  asm volatile("ldc1 $f15, %0" : : "m"(s->regs[15]));
  asm volatile("ldc1 $f16, %0" : : "m"(s->regs[16]));
  asm volatile("ldc1 $f17, %0" : : "m"(s->regs[17]));
  asm volatile("ldc1 $f18, %0" : : "m"(s->regs[18]));
  asm volatile("ldc1 $f19, %0" : : "m"(s->regs[19]));
  asm volatile("ldc1 $f20, %0" : : "m"(s->regs[20]));
  asm volatile("ldc1 $f21, %0" : : "m"(s->regs[21]));
  asm volatile("ldc1 $f22, %0" : : "m"(s->regs[22]));
  asm volatile("ldc1 $f23, %0" : : "m"(s->regs[23]));
  asm volatile("ldc1 $f24, %0" : : "m"(s->regs[24]));
  asm volatile("ldc1 $f25, %0" : : "m"(s->regs[25]));
  asm volatile("ldc1 $f26, %0" : : "m"(s->regs[26]));
  asm volatile("ldc1 $f27, %0" : : "m"(s->regs[27]));
  asm volatile("ldc1 $f28, %0" : : "m"(s->regs[28]));
  asm volatile("ldc1 $f29, %0" : : "m"(s->regs[29]));
  asm volatile("ldc1 $f30, %0" : : "m"(s->regs[30]));
  asm volatile("ldc1 $f31, %0" : : "m"(s->regs[31]));
#else
  asm volatile("ldc1 $f0, %0" : : "m"(s->regs[0]));
  asm volatile("ldc1 $f2, %0" : : "m"(s->regs[1]));
  asm volatile("ldc1 $f4, %0" : : "m"(s->regs[2]));
  asm volatile("ldc1 $f6, %0" : : "m"(s->regs[3]));
  asm volatile("ldc1 $f8, %0" : : "m"(s->regs[4]));
  asm volatile("ldc1 $f10, %0" : : "m"(s->regs[5]));
  asm volatile("ldc1 $f12, %0" : : "m"(s->regs[6]));
  asm volatile("ldc1 $f14, %0" : : "m"(s->regs[7]));
  asm volatile("ldc1 $f16, %0" : : "m"(s->regs[8]));
  asm volatile("ldc1 $f18, %0" : : "m"(s->regs[9]));
  asm volatile("ldc1 $f20, %0" : : "m"(s->regs[10]));
  asm volatile("ldc1 $f22, %0" : : "m"(s->regs[11]));
  asm volatile("ldc1 $f24, %0" : : "m"(s->regs[12]));
  asm volatile("ldc1 $f26, %0" : : "m"(s->regs[13]));
  asm volatile("ldc1 $f28, %0" : : "m"(s->regs[14]));
  asm volatile("ldc1 $f30, %0" : : "m"(s->regs[15]));
#endif
  asm volatile("ctc1 %0, $31" : : "r"(s->status));

  asm volatile(".set   pop\n");
}

void
c_vcpu_entry(l4_vcpu_state_t *vcpu)
{
  if (!(vcpu->r.status & (1UL << 3)))
    {
      Err().printf("Exception in entry handler. Halting. IP = 0x%lx\n",
                   vcpu->r.ip);
      guest->halt_vm();
    }

  Vmm::Vcpu_ptr c(vcpu);
  save_fpu(c.fpu_state());

  guest->handle_entry(c);

  restore_fpu(c.fpu_state());

  L4::Cap<L4::Thread> myself;
  auto e = l4_error(myself->vcpu_resume_commit(myself->vcpu_resume_start()));

  Err().printf("VM restart failed with %ld\n", e);
  guest->halt_vm();
}

Vmm::Guest *
Vmm::Guest::create_instance()
{
  guest.construct();
  return guest;
}
