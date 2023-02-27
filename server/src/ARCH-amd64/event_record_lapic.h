/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include "event_record.h"
#include "virt_lapic.h"

namespace Vmm
{

/**
 * NMI event record.
 */
struct Event_nmi : Event_record
{
  Event_nmi(Gic::Virt_lapic *apic) : Event_record(Event_prio::Nmi), lapic(apic)
  {}

  bool inject(Vm_state *vm) override;

  Gic::Virt_lapic *lapic;
};

/**
 * IRQ event record.
 */
struct Event_irq : Event_record
{
  Event_irq(Gic::Virt_lapic *apic) : Event_record(Event_prio::Irq), lapic(apic)
  {}

  bool inject(Vm_state *vm) override;

  Gic::Virt_lapic *lapic;
};

} // namespace Vmm
