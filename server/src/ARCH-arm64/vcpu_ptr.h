/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>

#include "aarch64_hyp.h"
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
    asm volatile ("mrs %0, CNTFRQ_EL0" : "=r"(x));
    return x;
  }

  static l4_uint64_t cntvct()
  {
    l4_uint64_t x;
    asm volatile ("mrs %0, CNTVCT_EL0" : "=r"(x));
    return x;
  }

  static l4_uint64_t cntv_cval()
  {
    l4_uint64_t x;
    asm volatile ("mrs %0, CNTV_CVAL_EL0" : "=r"(x));
    return x;
  }

  void *saved_tls() const
  { return reinterpret_cast<void **>((char *)_s + L4_VCPU_OFFSET_EXT_INFOS)[1]; }

  l4_utcb_t *restore_on_entry() const
  {
    asm volatile("msr TPIDR_EL0, %0" : : "r"(saved_tls()));
    return reinterpret_cast<l4_utcb_t **>((char *)_s + L4_VCPU_OFFSET_EXT_INFOS)[0]; 
  }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
    void **x = reinterpret_cast<void **>((char *)_s + L4_VCPU_OFFSET_EXT_INFOS);
    x[0] = l4_utcb();
    asm volatile ("mrs %0, TPIDR_EL0" : "=r"(x[1]));
  }

  Arm::State *state()
  { return reinterpret_cast<Arm::State *>((char *)_s + L4_VCPU_OFFSET_EXT_STATE); }

  Arm::Hsr hsr() const
  { return Arm::Hsr(_s->r.err); }

  void jump_instruction() const
  { _s->r.ip += 2 << hsr().il(); }

  l4_umword_t get_gpr(unsigned x) const
  {
    if (x < 31)
      return _s->r.r[x];
    else
      return 0;
  }

  void set_gpr(unsigned x, l4_umword_t value) const
  {
    if (x < 31)
      _s->r.r[x] = value;
  }

  Mem_access decode_mmio() const
  {
    Mem_access m;

    if (!hsr().pf_isv())
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
