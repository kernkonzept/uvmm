/*
 * Copyright (C) 2015 Kernkonzept GmbH.
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
        // assembly implementation of
        // switch(x - 8) {
        //    case n:
        //        read banked fiq register (n + 8)
        //        break;
        asm ("add pc, pc, %[r]\n"
             "nop\n"
             "mrs %[res], R8_fiq \n b 2f\n"
             "mrs %[res], R9_fiq \n b 2f\n"
             "mrs %[res], R10_fiq\n b 2f\n"
             "mrs %[res], R11_fiq\n b 2f\n"
             "mrs %[res], R12_fiq\n b 2f\n"
             "mrs %[res], SP_fiq \n b 2f\n"
             "mrs %[res], LR_fiq \n"
             "2:\n" : [res]"=r"(res) : [r]"r"((x - 8) * 8));
        return res;
      }

    // Should we check whether we have a valid mode (irq, svc, abt, und) here?
    //
    // assembly implementation of
    // switch(f(mode, x-13)) {
    //    case x:
    //        read banked lr/sp register for mode
    //        break;
    asm ("add pc, pc, %[r]\n"
         "nop\n"
         "mrs %[res], SP_irq \n b 2f\n"
         "mrs %[res], LR_irq \n b 2f\n"
         "mrs %[res], SP_svc\n b 2f\n"
         "mrs %[res], LR_svc\n b 2f\n"
         "mrs %[res], SP_abt\n b 2f\n"
         "mrs %[res], LR_abt \n b 2f\n"
         "mrs %[res], SP_und \n b 2f\n"
         "mrs %[res], LR_und \n"
         "2:\n" : [res]"=r"(res) : [r]"r"((x - 13 + mode_offs()) * 8));
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
        // assembly implementation of
        // switch(x - 8) {
        //    case n:
        //        write banked fiq register (n + 8)
        //        break;
        asm ("add pc, pc, %[r]\n"
             "nop\n"
             "msr R8_fiq,  %[v] \n b 2f\n"
             "msr R9_fiq,  %[v] \n b 2f\n"
             "msr R10_fiq, %[v] \n b 2f\n"
             "msr R11_fiq, %[v] \n b 2f\n"
             "msr R12_fiq, %[v] \n b 2f\n"
             "msr SP_fiq,  %[v] \n b 2f\n"
             "msr LR_fiq,  %[v] \n"
             "2:\n" : : [v]"r"(value), [r]"r"((x - 8) * 8));
        return;
      }

    // Should we check whether we have a valid mode (irq, svc, abt, und) here?
    //
    // assembly implementation of
    // switch(f(mode, x-13)) {
    //    case x:
    //        write banked lr/sp register for mode
    //        break;
    asm ("add pc, pc, %[r]\n"
         "nop\n"
         "msr SP_irq, %[v] \n b 2f\n"
         "msr LR_irq, %[v] \n b 2f\n"
         "msr SP_svc, %[v] \n b 2f\n"
         "msr LR_svc, %[v] \n b 2f\n"
         "msr SP_abt, %[v] \n b 2f\n"
         "msr LR_abt, %[v] \n b 2f\n"
         "msr SP_und, %[v] \n b 2f\n"
         "msr LR_und, %[v] \n"
         "2:\n" : : [v]"r"(value), [r]"r"((x - 13 + mode_offs()) * 8));
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
