/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "vcpu_ic.h"

namespace Gic {

Vcpu_ic::Vcpu_ic(Vmm::Vcpu_ptr vcpu, L4Re::Util::Object_registry *registry)
: _vcpu(vcpu),
  _cpu_irq(L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                        "Allocate vcpu notification irq.")),
  _registry(registry)
{
  L4Re::chksys(L4Re::Env::env()->factory()->create(_cpu_irq.get()),
                 "Create vcpu notification irq.");

  _registry->register_obj(this);
}

Vcpu_ic::~Vcpu_ic()
{
  _registry->unregister_obj(this);
}

void Vcpu_ic::attach_cpu_thread(L4::Cap<L4::Thread> thread)
{
  L4Re::chksys(
    _cpu_irq->bind_thread(thread, reinterpret_cast<l4_umword_t>(this)),
    "Bind vcpu notification irq.");
}

void Vcpu_ic::notify_ipi(Vmm::Vcpu_ptr current_vcpu)
{
  if (current_vcpu != _vcpu)
    notify(Interrupt_ipi);
  else
    set_ipi();
}

void Vcpu_ic::notify_timer()
{
  notify(Interrupt_timer);
}

void Vcpu_ic::notify_external(Vmm::Vcpu_ptr current_vcpu)
{
  if (current_vcpu != _vcpu)
    notify(Interrupt_external);
  else
    update_external();
}

void Vcpu_ic::notify(Interrupt interrupt)
{
  // Mark that interrupt has a update pending
  // TODO: Memory order?
  if (_update_pending.fetch_or(interrupt) == 0)
    // Notify vCPU in case no interrupt update was pending before.
    _cpu_irq->trigger();
}

void Vcpu_ic::set_external_pending(bool pending, Vmm::Vcpu_ptr current_vcpu)
{
  // TODO: Memory order?
  if (_external_pending.exchange(pending) != pending)
    // Notify vCPU in case the external interrupt pending state has changed
    notify_external(current_vcpu);
}

void Vcpu_ic::set_ipi()
{
  _vcpu.vm_state()->hvip |= L4_vm_hvip_vssip;
}

void Vcpu_ic::set_timer()
{
  _vcpu.vm_state()->hvip |= L4_vm_hvip_vstip;
}

void Vcpu_ic::clear_timer()
{
  _vcpu.vm_state()->hvip &= ~L4_vm_hvip_vstip;
}

void Vcpu_ic::update_external()
{
  // TODO: Memory order?
  if (_external_pending.load())
    _vcpu.vm_state()->hvip |= L4_vm_hvip_vseip;
  else
    _vcpu.vm_state()->hvip &= ~L4_vm_hvip_vseip;
}

void Vcpu_ic::handle_irq()
{
  // Fetch pending interrupt updates
  l4_uint32_t updates = _update_pending.exchange(0);

  if (updates & Interrupt_ipi)
    set_ipi();

  if (updates & Interrupt_timer)
    set_timer();

  if (updates & Interrupt_external)
    update_external();
}

} // namespace
