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
  explicit Event_nmi(Gic::Virt_lapic *apic)
  : Event_record(Event_prio::Nmi), lapic(apic)
  {}

  bool inject(Vm_state *vm) override;

  Gic::Virt_lapic *lapic;
};

/**
 * IRQ event record.
 */
struct Event_irq : Event_record
{
  explicit Event_irq(Gic::Virt_lapic *apic)
  : Event_record(Event_prio::Irq), lapic(apic)
  {}

  bool inject(Vm_state *vm) override;

  Gic::Virt_lapic *lapic;
};

// These are necessary to correctly compute Event_memory::max_event_size().
// The asserts ensure that these event objects don't influence the computation.
static_assert(sizeof(Event_irq) <= sizeof(Event_exc),
              "IRQ event objects are not the largest event object.");
static_assert(sizeof(Event_nmi) <= sizeof(Event_exc),
              "NMI event objects are not the largest event object.");

} // namespace Vmm
