/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021, 2023 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include "arm_exc.h"
#include "guest.h"

namespace Vmm {

namespace {

using namespace Arm;

void enter_exception64(Vcpu_ptr vcpu)
{
  l4_umword_t old_flags = vcpu->r.flags;
  l4_umword_t target_mode = Aarch64::Spsr_m_el1h;

  vcpu->r.flags = Aarch64::get_except_flags(vcpu, target_mode);
  asm volatile("msr SPSR_EL1, %0" : : "r"(old_flags));

  l4_umword_t mode = old_flags & Aarch64::Spsr_m_mask;
  unsigned exc_offset = Aarch64::get_except_offset(mode, target_mode);

  // Save current instruction pointer
  asm volatile("msr ELR_EL1, %0" : : "r"(vcpu->r.ip));

  // Set exception vector instruction pointer
  l4_umword_t vbar;
  asm volatile ("mrs %0, VBAR_EL1" : "=r"(vbar));
  vcpu->r.ip = vbar + exc_offset;
}

void enter_exception32(Vcpu_ptr vcpu, unsigned mode, Aarch32::Exc_offset off)
{
  l4_uint32_t spsr = vcpu->r.flags;

  vcpu->r.flags = Aarch32::get_except_flags(vcpu, mode);

  l4_addr_t return_addr =
    vcpu->r.ip + Aarch32::get_return_offset(off, spsr & Aarch32::Psr_t);
  // SPSR and LR are banked registers for the PE mode the exception is taken to.
  if (mode == Aarch32::Psr_m_und)
    {
      // TODO: The SPSR_und register can only be accessed from EL2 mode...
      asm volatile("msr SPSR_und, %x0" : : "r"(spsr));
      // LR_und is mapped to GPR X22 on Aarch64
      vcpu->r.r[22] = return_addr;
    }
  else if (mode == Aarch32::Psr_m_abt)
    {
      // TODO: The SPSR_abt register can only be accessed from EL2 mode...
      asm volatile("msr SPSR_abt, %x0" : : "r"(spsr));
      // LR_abt is mapped to GPR X20 on Aarch64
      vcpu->r.r[20] = return_addr;
    }

  l4_uint32_t vbar;
  if (l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR) & Aarch32::Sctlr_v)
    // The guest uses high exception vectors.
    vbar = 0xffff0000;
  else
    asm volatile ("mrs %x0, VBAR_EL1" : "=r"(vbar)); // VBAR

  vcpu->r.ip = vbar + static_cast<unsigned>(off);
}

/* Inject abort into Aarch32 guest on Aarch64 host */
__attribute__ ((unused))
void inject_abort32(Vcpu_ptr vcpu, bool inst, l4_uint32_t addr)
{
  l4_uint32_t ttbcr;
  asm volatile ("mrs %x0, TCR_EL1" : "=r"(ttbcr));
  l4_uint32_t fsr = Aarch32::get_abort_fsr(ttbcr);

  l4_uint64_t far;
  asm volatile ("mrs %0, FAR_EL1" : "=r"(far));

  Aarch32::Exc_offset off;
  if (inst)
    {
      off = Aarch32::Exc_offset::Prefetch_abort;

      // IFAR is mapped to FAR_EL1 bits [63:32]
      far &= (~0xffffffffULL) << 32;
      far |= static_cast<l4_uint64_t>(addr) << 32;

      // TODO: The IFSR32_EL2 register can only be accessed from EL2 mode...
      asm volatile("msr IFSR32_EL2, %x0" : : "r"(fsr));
    }
  else
    {
      off = Aarch32::Exc_offset::Data_abort;

      // DFAR is mapped to FAR_EL1 bits [31:0]
      far &= ~0xffffffffULL;
      far |= addr;

      asm volatile("msr ESR_EL1, %x0" : : "r"(fsr));
    }
  asm volatile("msr FAR_EL1, %0" : : "r"(far));

  enter_exception32(vcpu, Aarch32::Psr_m_abt, off);
}

/* Inject abort into Aarch64 guest on Aarch64 host */
void inject_abort64(Vcpu_ptr vcpu, bool inst, l4_addr_t addr)
{
  asm volatile("msr FAR_EL1, %0" : : "r"(addr));

  Hsr esr = Aarch64::get_abort_esr(vcpu, inst);
  asm volatile("msr ESR_EL1, %x0" : : "r"(esr.raw()));

  enter_exception64(vcpu);
}

__attribute__ ((unused))
void inject_undef32(Vcpu_ptr vcpu)
{
  enter_exception32(vcpu, Aarch32::Psr_m_und,
                    Aarch32::Exc_offset::Undefined_inst);
}

void inject_undef64(Vcpu_ptr vcpu)
{
  Hsr esr { 0 };
  esr.il() = vcpu.hsr().il();
  esr.ec() = Hsr::Ec_unknown;
  asm volatile("msr ESR_EL1, %x0" : : "r"(esr.raw()));

  enter_exception64(vcpu);
}

}

bool Guest::fault_mode_supported(Fault_mode mode)
{
  return mode == Fault_mode::Inject
         || Generic_guest::fault_mode_supported(mode);
}

bool
Guest::inject_abort(Vcpu_ptr vcpu, bool inst, l4_addr_t addr)
{
  if (Aarch64::is_aarch32(vcpu->r.flags))
    // TODO: inject_abort32(vcpu, inst, addr);
    return false;
  else
    inject_abort64(vcpu, inst, addr);

  return true;
}

bool
Guest::inject_undef(Vcpu_ptr vcpu)
{
  if (Aarch64::is_aarch32(vcpu->r.flags))
    // TODO: inject_undef32(vcpu);
    return false;
  else
    inject_undef64(vcpu);

  return true;
}

}
