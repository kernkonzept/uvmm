/*
 * Copyright (C) 2015-2021 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>

#include "aarch32_hyp.h"
#include "generic_vcpu_ptr.h"
#include "mem_access.h"

namespace Vmm {

class Vcpu_ptr : public Generic_vcpu_ptr
{
public:
  explicit Vcpu_ptr(l4_vcpu_state_t *s) : Generic_vcpu_ptr(s) {}

  bool pf_write() const
  { return hsr().pf_write(); }

  static l4_uint32_t cntfrq()
  {
    l4_uint32_t x;
    asm volatile("mrc  p15, 0, %0, c14, c0, 0" : "=r" (x));
    return x;
  }

  static l4_uint64_t cntvct()
  {
    l4_uint64_t x;
    asm volatile ("mrrc p15, 1, %Q0, %R0, c14" : "=r"(x));
    return x;
  }

  static l4_uint64_t cntv_cval()
  {
    l4_uint64_t x;
    asm volatile ("mrrc p15, 3, %Q0, %R0, c14" : "=r"(x));
    return x;
  }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
    reinterpret_cast<l4_utcb_t **>(l4_vcpu_e_info_user(_s))[0] = l4_utcb();
  }

  Arm::Hsr hsr() const
  { return Arm::Hsr(_s->r.err); }

  void jump_instruction() const
  { _s->r.ip += 2 << hsr().il(); }

  /**
   * Check whether register 'x' is a user mode register for the current mode
   *
   * \retval true   Register is a normal register accessible in l4_vcpu_state_t
   * \retval false  Register is a banked register which needs special treatment
   */
  bool use_ureg(unsigned x) const
  {
    // registers < 8 are always the user registers
    if (x < 8)
      return true;

    // one byte for each (legal) mode, where a set bit (x - 8) means
    // register r[x] is a user register, modes are
    //
    //   usr,  fiq,  irq,  svc,
    //      ,     ,  mon,  abt,
    //      ,     ,  hyp,  und,
    //      ,     ,     ,  sys
    //
    // fiq is handled separately, mon/hyp are invalid (trap to el2/el3).
    static l4_uint8_t const i[] =
      { 0xff, 0x00, 0x3f, 0x3f,
        0x00, 0x00, 0x00, 0x3f,
        0x00, 0x00, 0x00, 0x3f,
        0x00, 0x00, 0x00, 0xff };

    return i[_s->r.flags & 0x0f] & (1 << (x - 8));
  }

  /**
   * Caculate jump offset used for accessing non-user SP and LR in
   * 'irq', 'svc', 'abt' or 'und' mode
   *
   * The calculation does not check whether the mode is valid.
   *
   * \return  Jump offset
   */
  unsigned mode_offs() const
  {
    // mode (lower 5bits of flags):
    //
    //   0x12 -> 0, irq
    //   0x13 -> 2, svc
    //   0x17 -> 4, abt
    //   0x1b -> 6, und
    //
    // all other (non hyp) modes use all user registers, are handled
    // separately (fiq) or are illegal
    return ((_s->r.flags + 1) >> 1) & 0x6;
  }

  l4_umword_t get_gpr(unsigned x) const
  {
    if (L4_UNLIKELY(x > 14))
      return 0;

    if (use_ureg(x))
      switch (x)
        {
        case 14: return _s->r.lr;
        case 13: return _s->r.sp;
        default: return _s->r.r[x];
        }

    if (0)
      printf("SPECIAL GET GPR: m=%2lx x=%u\n", (_s->r.flags & 0x1f), x);

    l4_umword_t res;
    if ((_s->r.flags & 0x1f) == 0x11) // FIQ
      {
        switch (x - 8)
          {
          case 0: asm ("mrs %[res], R8_fiq " : [res]"=r"(res)); break;
          case 1: asm ("mrs %[res], R9_fiq " : [res]"=r"(res)); break;
          case 2: asm ("mrs %[res], R10_fiq" : [res]"=r"(res)); break;
          case 3: asm ("mrs %[res], R11_fiq" : [res]"=r"(res)); break;
          case 4: asm ("mrs %[res], R12_fiq" : [res]"=r"(res)); break;
          case 5: asm ("mrs %[res], SP_fiq " : [res]"=r"(res)); break;
          case 6: asm ("mrs %[res], LR_fiq " : [res]"=r"(res)); break;
          default: __builtin_unreachable();
          }
        return res;
      }

    // Should we check whether we have a valid mode (irq, svc, abt, und) here?
    switch (x - 13 + mode_offs())
      {
      case 0: asm ("mrs %[res], SP_irq" : [res]"=r"(res)); break;
      case 1: asm ("mrs %[res], LR_irq" : [res]"=r"(res)); break;
      case 2: asm ("mrs %[res], SP_svc" : [res]"=r"(res)); break;
      case 3: asm ("mrs %[res], LR_svc" : [res]"=r"(res)); break;
      case 4: asm ("mrs %[res], SP_abt" : [res]"=r"(res)); break;
      case 5: asm ("mrs %[res], LR_abt" : [res]"=r"(res)); break;
      case 6: asm ("mrs %[res], SP_und" : [res]"=r"(res)); break;
      case 7: asm ("mrs %[res], LR_und" : [res]"=r"(res)); break;
      default: __builtin_unreachable();
      }

    return res;
  }

  void set_gpr(unsigned x, l4_umword_t value) const
  {
    if (L4_UNLIKELY(x > 14))
      return;

    if (use_ureg(x))
      switch (x)
        {
        case 14: _s->r.lr = value; return;
        case 13: _s->r.sp = value; return;
        default: _s->r.r[x] = value; return;
        }

    if (0)
      printf("SPECIAL SET GPR: m=%2lx x=%u\n", (_s->r.flags & 0x1f), x);

    if ((_s->r.flags & 0x1f) == 0x11) // FIQ
      {
        switch (x - 8)
          {
          case 0: asm ("msr R8_fiq,  %[v]" : : [v]"r"(value)); break;
          case 1: asm ("msr R9_fiq,  %[v]" : : [v]"r"(value)); break;
          case 2: asm ("msr R10_fiq, %[v]" : : [v]"r"(value)); break;
          case 3: asm ("msr R11_fiq, %[v]" : : [v]"r"(value)); break;
          case 4: asm ("msr R12_fiq, %[v]" : : [v]"r"(value)); break;
          case 5: asm ("msr SP_fiq,  %[v]" : : [v]"r"(value)); break;
          case 6: asm ("msr LR_fiq,  %[v]" : : [v]"r"(value)); break;
          default: __builtin_unreachable();
          }
        return;
      }

    // Should we check whether we have a valid mode (irq, svc, abt, und) here?
    switch (x - 13 + mode_offs())
      {
      case 0: asm ("msr SP_irq, %[v]" : : [v]"r"(value)); break;
      case 1: asm ("msr LR_irq, %[v]" : : [v]"r"(value)); break;
      case 2: asm ("msr SP_svc, %[v]" : : [v]"r"(value)); break;
      case 3: asm ("msr LR_svc, %[v]" : : [v]"r"(value)); break;
      case 4: asm ("msr SP_abt, %[v]" : : [v]"r"(value)); break;
      case 5: asm ("msr LR_abt, %[v]" : : [v]"r"(value)); break;
      case 6: asm ("msr SP_und, %[v]" : : [v]"r"(value)); break;
      case 7: asm ("msr LR_und, %[v]" : : [v]"r"(value)); break;
      default: __builtin_unreachable();
      }
  }

  l4_umword_t get_sp() const
  {
    return get_gpr(13);
  }

  l4_umword_t get_lr() const
  {
    return get_gpr(14);
  }

  Mem_access decode_mmio() const
  {
    Mem_access m;

    if (!hsr().pf_isv() || hsr().pf_srt() > 14)
      {
        m.access = Mem_access::Other;
        return m;
      }

    m.width = hsr().pf_sas();
    m.access = hsr().pf_write() ? Mem_access::Store : Mem_access::Load;

    if (m.access == Mem_access::Store)
      m.value = get_gpr(hsr().pf_srt());

    return m;
  }

  void writeback_mmio(Mem_access const &m) const
  {
    assert(m.access == Mem_access::Load);

    l4_umword_t v = reg_extend_width(m.value, hsr().pf_sas(), hsr().pf_sse());
    set_gpr(hsr().pf_srt(), v);
  }
};

} // namespace
