/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

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

  unsigned get_vcpu_id() const
  { return *(reinterpret_cast<unsigned char const *>(_s) + 0x208); }

  void set_vcpu_id(unsigned id)
  { *(reinterpret_cast<unsigned char *>(_s) + 0x208) = id; }

  Arm::Hsr hsr() const
  { return Arm::Hsr(_s->r.err); }
};

} // namespace
