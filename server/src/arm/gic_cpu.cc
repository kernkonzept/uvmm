/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2013-2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "gic_cpu.h"

namespace Gic {

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

void Vcpu_handler::handle_migrations()
{
  fetch_pending_irqs();
  for (auto it = _owned_pend_irqs.begin(); it != _owned_pend_irqs.end();)
    {
      if (!it->is_pending_and_enabled() || !it->is_for_cpu(vcpu_id()))
        {
          Irq *removed = *it;
          it = _owned_pend_irqs.erase(it);
          if (removed->is_pending_and_enabled())
            {
              // Irq is pending&enabled after we removed it from our list.
              // Make sure it is queued again on the right target cpu.
              Vcpu_handler *cpu = removed->vcpu_handler();
              cpu->queue(removed);
              cpu->notify_irq();
            }
        }
      else
        ++it;
    }
}

void Vcpu_handler::fetch_pending_irqs()
{
  // Atomically move newly pending Irqs here so that we can work on them
  // without having to bother about concurrent list modifications.
  Atomic_fwd_list<Irq> tmp;
  tmp.swap(_pending_irqs);

  // Move newly arrived pending IRQs to our own, sorted list. A remove-insert
  // sequence is not possible because there must be no point in time where a
  // pending&enabled IRQ is not on a list.
  for (auto n = tmp.begin(); n != tmp.end();)
    {
      auto pos = _owned_pend_irqs.before_begin();
      for (;;)
        {
          auto next = pos;
          ++next;
          if (next == _owned_pend_irqs.end() || next->prio() > n->prio())
            break;
          pos = next;
        }

      n = _owned_pend_irqs.move_after(pos, tmp, n);
    }

  // We could sort the list again if the guest changed the priorities. But
  // this overhead would be payed always which it not worth this corner case.
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
