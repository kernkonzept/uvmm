/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#pragma once

#include "arm_hyp.h"
#include "vcpu_ptr.h"

namespace Vmm {
namespace Arm {

namespace Aarch32 {

enum Psr
{
  Psr_t     = 1UL << 5,
  Psr_f     = 1UL << 6,
  Psr_i     = 1UL << 7,
  Psr_a     = 1UL << 8,
  Psr_e     = 1UL << 9,

  Psr_ge_mask = 0xfUL << 16,

  // Shared with ARM64
  Psr_pan  = 1UL << 22,
  Psr_ssbs = 1UL << 23,
  Psr_dit  = 1UL << 24,

  // Shared with ARM64
  Psr_q = 1UL << 27,
  Psr_v = 1UL << 28,
  Psr_c = 1UL << 29,
  Psr_z = 1UL << 30,
  Psr_n = 1UL << 31,

  Psr_m_fiq = 0x11,
  Psr_m_svc = 0x13,
  Psr_m_abt = 0x17,
  Psr_m_und = 0x1b,
};

enum class Exc_offset
{
  Undefined_inst = 4,
  Prefetch_abort = 12,
  Data_abort     = 16,
};

enum Fsr
{
  Fsr_fs_ext_abort_nlpae = 0x08,
  Fsr_fs_ext_abort_lpae  = 0x10,
  Fsr_lpae               = 1UL << 9,
};

enum Sctlr
{
  Sctlr_v     = 1UL << 13,
  Sctlr_span  = 1UL << 23,
  Sctlr_ee    = 1UL << 25,
  Sctlr_te    = 1UL << 30,
  Sctlr_dssbs = 1UL << 31,
};

/**
 * On exception entry, the preferred return address for the exception is saved
 * in the link register of the mode the exception is taken to. If the exception
 * is taken to a non-EL2 mode, additionally an instruction-specific offset must
 * be added to the preferred return address.
 *
 * \param off    Exception to be taken
 * \param thumb  Indicates whether the trapped instruction is a Thumb
 *               instruction.
 *
 * \return The adjustment for the preferred return offset.
 */
inline unsigned get_return_offset(Exc_offset off, bool thumb)
{
  switch (off)
    {
    case Exc_offset::Undefined_inst:
      return thumb ? 2 : 4;
    case Exc_offset::Prefetch_abort:
      return 4;
    case Exc_offset::Data_abort:
      return 8;
    }
  return 0;
}

/**
 * Derive the PSTATE flags for an Aarch32 exception handler handling an
 * exception taken from Aarch32 state.
 *
 * \param vcpu  vCPU on which the exception is taken
 * \param mode  Mode to which the exception is taken
 *
 * \return PSTATE flags for the exception handler.
 */
inline l4_uint32_t get_except_flags(Vcpu_ptr vcpu, unsigned mode)
{
  l4_uint32_t sctlr = l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR);
  l4_umword_t old_flags = vcpu->r.flags;
  l4_uint32_t new_flags = 0;

  // The condition flags are preserved
  new_flags = old_flags & (Psr_n | Psr_z | Psr_c | Psr_v | Psr_q | Psr_ge_mask);

  // CPSR.DIT is preserved
  new_flags |= old_flags & Psr_dit;

  // CPSR.SSBS is set to SCTLR_ELx.DSSBS
  if (sctlr & Sctlr_dssbs)
    new_flags |= Psr_ssbs;

  // CPSR.PAN is preserved unless overridden by SCTLR_ELx.SPAN
  new_flags |= (old_flags & Psr_pan);
  if (!(sctlr & Sctlr_span))
    new_flags |= Psr_pan;

  // CPSR.E is set to SCTLR.EE
  if (sctlr & Sctlr_ee)
    new_flags |= Psr_e;

  // CPSR.A is preserved on an exception to Supervisor or Undefined mode, for
  // other modes it is set to 1
  if (mode == Psr_m_und || mode == Psr_m_svc)
    new_flags |= (old_flags & Psr_a);
  else
    new_flags |= Psr_a;

  // CPSR.I is set to 1
  new_flags |= Psr_i;

  // CPSR.F is set on an exception to FIQ mode, for other modes it is preserved
  if (mode == Psr_m_fiq)
    new_flags |= Psr_f;
  else
    new_flags |= (old_flags & Psr_f);

  // CPSR.T is set to SCTLR.TE
  if (sctlr & Sctlr_te)
    new_flags |= Psr_t;

  // CPSR.M is set to the mode to which the exception is taken
  new_flags |= mode;

  return new_flags;
}

/**
 * Generate fault status information for prefetch and data aborts.
 *
 * IFSR and DFSR use the same bit assignment for the bits that are relevant for
 * us.
 */
inline l4_uint32_t get_abort_fsr(l4_uint32_t ttbcr)
{
  if (ttbcr & Ttbcr_eae)
    // LPAE is enabled
    return Fsr_lpae | Fsr_fs_ext_abort_lpae;
  else
    // LPAE is not enabled
    return Fsr_fs_ext_abort_nlpae;
}

}

namespace Aarch64 {

enum Spsr
{
  Spsr_m_sp      = 1UL << 0,
  Spsr_m_el0t    = 0,
  Spsr_m_el1h    = (1UL << 2) | Spsr_m_sp,
  Spsr_m_aarch32 = 1UL << 4,
  Spsr_m_mask    = 0x1f,

  Spsr_f = 1UL << 6,
  Spsr_i = 1UL << 7,
  Spsr_a = 1UL << 8,
  Spsr_d = 1UL << 9,

  Spsr_ssbs = 1UL << 12,
  Spsr_pan  = 1UL << 22,
  Spsr_dit  = 1UL << 24,

  Spsr_v = 1UL << 28,
  Spsr_c = 1UL << 29,
  Spsr_z = 1UL << 30,
  Spsr_n = 1UL << 31,
};

enum Sctlr_el1
{
  Sctlr_el1_span = 1ULL << 23,
  Sctlr_el1_dssbs = 1ULL << 44,
};

enum Vector
{
  Vector_current_el_sp_el0 = 0,
  Vector_current_el_sp_elx = 0x200,
  Vector_lower_el_aarch64  = 0x400,
  Vector_lower_el_aarch32  = 0x600,
};

inline bool is_aarch32(unsigned mode)
{
  return mode & Spsr_m_aarch32;
}

/**
 * Derive the PSTATE flags for an Aarch64 exception handler handling an
 * exception taken from Aarch32 or Aarch64 state.
 *
 * The layout of SPSR differs slightly depending on whether the exception is
 * taken from Aarch32 or Aarch64 state. However, we do not need to differentiate
 * between these two scenarios here, as the differences are limited to flags
 * that are not relevant for deriving the PSTATE flags for an Aarch64 exception
 * handler.
 *
 * \param vcpu  vCPU on which the exception is taken
 * \param mode  Mode to which the exception is taken
 *
 * \return PSTATE flags for the exception handler.
 */
inline l4_umword_t get_except_flags(Vcpu_ptr vcpu, l4_umword_t mode)
{
  // TODO: Fiasco only saves/restores the lower 32-bit of SCTRL, thus the below
  //       test for Sctlr_el1_dssbs will always fail.
  l4_umword_t sctlr = l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR);
  l4_umword_t old_flags = vcpu->r.flags;
  l4_umword_t new_flags = 0;

  // The condition flags are preserved
  new_flags |= old_flags & (Spsr_n | Spsr_z | Spsr_c | Spsr_v);

  // PSTATE.DIT is preserved
  new_flags |= old_flags & Spsr_dit;

  // PSTATE.UAO is set to 0

  // PSTATE.PAN is preserved unless overridden by SCTLR_ELx.SPAN
  new_flags |= (old_flags & Spsr_pan);
  if (!(sctlr & Sctlr_el1_span))
    new_flags |= Spsr_pan;

  // PSTATE.SS and PSTATE.IL are set to 0

  // PSTATE.SSBS is set to SCTLR_ELx.DSSBS
  if (sctlr & Sctlr_el1_dssbs)
    new_flags |= Spsr_ssbs;

  // PSTATE.BTYPE is set to 0

  // The exception mask bits are set
  new_flags |= Spsr_d | Spsr_a |  Spsr_i | Spsr_f;

  // PSTATE.M is set to the mode to which the exception is taken
  new_flags |= mode;

  return new_flags;
}

/**
 * Get the offset in the vector table depending on both the mode in which the
 * exception occurred and the mode to which it is taken.
 *
 * \param mode         Mode in which the exception occurred
 * \param target_mode  Mode to which the exception is taken
 *
 * \return Vector table offset
 */
inline unsigned get_except_offset(l4_umword_t mode, l4_umword_t target_mode)
{
  if (mode == target_mode)
    return Vector_current_el_sp_elx;
  else if ((mode | Spsr_m_sp) == target_mode)
    return Vector_current_el_sp_el0;
  else if (!is_aarch32(mode))
    return Vector_lower_el_aarch64;
  else
    return Vector_lower_el_aarch32;
}

inline Hsr get_abort_esr(Vcpu_ptr vcpu, bool inst)
{
  Hsr esr { 0 };
  esr.il() = vcpu.hsr().il();

  l4_umword_t mode = vcpu->r.flags & Spsr_m_mask;
  bool from_lower = is_aarch32(mode) || (mode == Spsr_m_el0t);
  if (inst)
    esr.ec() = from_lower ? Hsr::Ec_iabt_low : Hsr::Ec_iabt_cur;
  else
    esr.ec() = from_lower ? Hsr::Ec_dabt_low : Hsr::Ec_dabt_cur;

  esr.pf_fsc() = Hsr::Fsc_sync_ext_abt;
  return esr;
}

}

}
}
