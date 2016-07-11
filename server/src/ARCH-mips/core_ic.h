/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>
#include <cstdio>

#include <l4/cxx/bitfield>

#include "irq.h"
#include "vcpu.h"

namespace Gic {

class Mips_core_ic : public Ic
{
  struct Hw_int_reg
  {
    l4_umword_t raw;
    CXX_BITFIELD_MEMBER(10, 15, hw_ints, raw);
  };

public:
  Mips_core_ic() : _irqvec(0), _pending{ 0, }
  {}

  void init_device(Vdev::Device_lookup const *,
                   Vdev::Dt_node const &) override
  {}

  void set(unsigned irq) override
  {
    assert(2 <= irq && irq <= 7);
    if (++_pending[irq - 2] == 1)
      _irqvec |= 1UL << (irq - 2);
  }

  void clear(unsigned irq) override
  {
    assert(2 <= irq && irq <= 7);
    if (--_pending[irq - 2] == 0)
      _irqvec &= ~(1UL << (irq - 2));
  }

  void bind_irq_source(unsigned, cxx::Ref_ptr<Irq_source>) override
  {
    L4Re::chksys(-L4_ENOSYS, "unmask not supported for Core IC. "
                             "Use GIC for devices that require EOI via IC.");
  }

  int dt_get_num_interrupts(Vdev::Dt_node const &node) override
  {
    int size;
    if (!node.get_prop<fdt32_t>("interrupts", &size))
      return 0;

    return size;
  }

  unsigned dt_get_interrupt(Vdev::Dt_node const &node, int irq)
  {
    auto *prop = node.check_prop<fdt32_t>("interrupts", irq + 1);

    return fdt32_to_cpu(prop[irq]);
  }

  void update_vcpu(Vmm::Cpu vcpu)
  {
    Hw_int_reg *gc2 = (Hw_int_reg *) &vcpu.state()->guest_ctl_2;
    l4_uint32_t oldvec = gc2->hw_ints();

    if (oldvec == _irqvec)
      return;

    gc2->hw_ints() = _irqvec;
    vcpu.state()->set_modified(L4_VM_MOD_GUEST_CTL_2);
  }

  void show_state(FILE *f, Vmm::Cpu vcpu)
  {
    auto *s = vcpu.state();
    s->update_state(L4_VM_MOD_STATUS);
    unsigned imask = s->g_status >> 10;
    unsigned ipending = s->g_cause >> 10;

    for (unsigned i = 0; i < 6; ++i)
      fprintf(f, " Int %d: %d (HW: %s/%s)\n", i + 2,
              _pending[i],
              imask & (1 << i) ? "on" : "off",
              ipending & (1 << i) ? "pending" : "low");
  }

private:
  l4_uint32_t _irqvec;
  int _pending[6];
};

} // namespace
