/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include "arm_exc.h"
#include "guest.h"

namespace Vmm {

namespace {

using namespace Arm;

void enter_exception(Vcpu_ptr vcpu, unsigned mode, Aarch32::Exc_offset off)
{
  l4_uint32_t spsr = vcpu->r.flags;

  vcpu->r.flags = Aarch32::get_except_flags(vcpu, mode);

  l4_addr_t return_addr =
    vcpu->r.ip + Aarch32::get_return_offset(off, spsr & Aarch32::Psr_t);

  // SPSR and LR are banked registers for the PE mode the exception is taken to.
  if (mode == Aarch32::Psr_m_und)
    {
      asm volatile("msr SPSR_und, %0" : : "r"(spsr));
      asm volatile("msr LR_und, %0" : : "r"(return_addr));
    }
  else if (mode == Aarch32::Psr_m_abt)
    {
      asm volatile("msr SPSR_abt, %0" : : "r"(spsr));
      asm volatile("msr LR_abt, %0" : : "r"(return_addr));
    }

  l4_uint32_t vbar;
  if (l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR) & Aarch32::Sctlr_v)
    // The guest uses high exception vectors.
    vbar = 0xffff0000;
  else
    asm volatile ("mrc p15, 0, %0, c12, c0, 0" : "=r"(vbar)); // VBAR

  vcpu->r.ip = vbar + static_cast<unsigned>(off);
}

}

bool Guest::fault_mode_supported(Fault_mode mode)
{
  return mode == Fault_mode::Inject
         || Generic_guest::fault_mode_supported(mode);
}

bool Guest::inject_abort(Vcpu_ptr vcpu, bool inst, l4_addr_t addr)
{
  l4_uint32_t ttbcr;
  asm volatile ("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr)); // TTBCR
  l4_uint32_t fsr = Aarch32::get_abort_fsr(ttbcr);

  Aarch32::Exc_offset off;
  if (inst)
    {
      off = Aarch32::Exc_offset::Prefetch_abort;
      asm volatile("mcr p15, 0, %0, c6, c0, 2 " : : "r"(addr)); // IFAR
      asm volatile("mcr p15, 0, %0, c5, c0, 1 " : : "r"(fsr)); // IFSR
    }
  else
    {
      off = Aarch32::Exc_offset::Data_abort;
      asm volatile("mcr p15, 0, %0, c6, c0, 0 " : : "r"(addr)); // DFAR
      asm volatile("mcr p15, 0, %0, c5, c0, 0 " : : "r"(fsr)); // DFSR
    }

  enter_exception(vcpu, Aarch32::Psr_m_abt, off);
  return true;
}

bool Guest::inject_undef(Vcpu_ptr vcpu)
{
  enter_exception(vcpu, Aarch32::Psr_m_und,
                  Aarch32::Exc_offset::Undefined_inst);
  return true;
}

}
