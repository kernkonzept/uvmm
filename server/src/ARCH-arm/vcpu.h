/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>

#include "arm_hyp.h"
#include "generic_vcpu.h"

namespace Vmm {

class Cpu : public Generic_cpu
{
public:
  explicit Cpu(l4_vcpu_state_t *s) : Generic_cpu(s) {}

  bool pf_write() const
  { return hsr().pf_write(); }

  l4_utcb_t *saved_utcb() const
  { return *reinterpret_cast<l4_utcb_t **>((char *)_s + L4_VCPU_OFFSET_EXT_INFOS); }

  void thread_attach()
  {
    control_ext(L4::Cap<L4::Thread>());
    *reinterpret_cast<l4_utcb_t **>((char *)_s + L4_VCPU_OFFSET_EXT_INFOS) = l4_utcb();
  }

  Arm::State *state()
  { return reinterpret_cast<Arm::State *>((char *)_s + L4_VCPU_OFFSET_EXT_STATE); }

  Arm::Hsr hsr() const
  { return Arm::Hsr(_s->r.err); }

  void jump_instruction() const
  { _s->r.ip += 2 << hsr().il(); }

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
      {
        switch (hsr().pf_srt())
          {
          case 13:
            m.value = _s->r.sp;
            break;
          case 14:
            m.value = _s->r.lr;
            break;
          default:
            m.value = _s->r.r[hsr().pf_srt()];
            break;
          }
      }

    return m;
  }

  void writeback_mmio(Mem_access const &m) const
  {
    assert(m.access == Mem_access::Load);

    l4_umword_t v = reg_extend_width(m.value, hsr().pf_sas(), hsr().pf_sse());

    switch (hsr().pf_srt())
      {
      case 13:
        _s->r.sp = v;
        break;
      case 14:
        _s->r.lr = v;
        break;
      default:
        _s->r.r[hsr().pf_srt()] = v;
        break;
      }
  }
};

} // namespace
