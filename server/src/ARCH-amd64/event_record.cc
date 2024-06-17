/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "event_record.h"
#include "event_record_lapic.h"

namespace Vmm {

bool Event_exc::inject(Vm_state *vm)
{
  vm->inject_event(
    Injection_event(ev_num, 3, error_val != Invalid_error, error_val));
  return true;
}

bool Real_mode_exc::inject(Vm_state *vm)
{
  vm->inject_event(Injection_event(ev_num, 3, false));
  return true;
}

bool Event_nmi::inject(Vm_state *vms)
{
  if (vms->can_inject_nmi())
    {
      vms->disable_nmi_window();
      lapic->next_pending_nmi();
      vms->inject_event(Injection_event(2, 2, false)); // NMI is vector 2, type 2
      return true;
    }

  vms->enable_nmi_window();
  return false;
}

bool Event_irq::inject(Vm_state *vms)
{
  if (vms->can_inject_interrupt())
    {
      vms->disable_interrupt_window();
      int irq = lapic->next_pending_irq();
      if (irq < 0)
        {
          return true;
        }

      vms->inject_event(Injection_event(irq, 0, false)); // IRQ vector, type 0
      return true;
    }

  vms->enable_interrupt_window();
  return false;
}

} // namespace Vmm
