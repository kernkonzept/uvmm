/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2013-2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "gic.h"

namespace Gic {

Dist_if::Factory const *Dist_if::Factory::_factory[4];

Dist::Dist(unsigned tnlines, unsigned max_cpus)
: gicd_trace(Dbg::Irq, Dbg::Trace, "GICD"), ctlr(0), tnlines(tnlines),
  _cpu(max_cpus),
  _spis(tnlines * 32)
{
}

static bool atomic_set_bits(uint32_t *addr, uint32_t mask)
{
  l4_uint32_t old = __atomic_load_n(addr, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;

  do
    {
      nv = old | mask;
      if (nv == old)
        return false;
    }
  while (!__atomic_compare_exchange_n(addr, &old, nv, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

  return true;
}

static void atomic_clear_bits(uint32_t *addr, uint32_t bits)
{
  l4_uint32_t old = __atomic_load_n(addr, __ATOMIC_ACQUIRE);
  l4_uint32_t mask = ~bits;
  l4_uint32_t nv;
  do
    {
      nv = old & mask;
      if (nv == old)
        return;
    }
  while (!__atomic_compare_exchange_n(addr, &old, nv, true,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

bool Cpu::set_sgi(unsigned irq)
{
  unsigned reg = irq / 4;
  unsigned field_off = irq % 4;
  l4_uint32_t bit = 1UL << (field_off * 8 + vmm_current_cpu_id);

  return atomic_set_bits(&_sgi_pend[reg], bit);
}

void Cpu::clear_sgi(unsigned irq, unsigned src)
{
  unsigned reg = irq / 4;
  unsigned field_off = irq % 4;
  l4_uint32_t bit = (1UL << (field_off * 8 + src));

  atomic_clear_bits(&_sgi_pend[reg], bit);
}

void
Cpu::dump_sgis() const
{
  for (auto const &pending : _sgi_pend)
    printf("%02x ", pending);
  puts("");
}

} // Gic
