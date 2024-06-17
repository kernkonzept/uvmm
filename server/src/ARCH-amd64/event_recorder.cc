/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "event_recorder.h"
#include "debug.h"

namespace Vmm {

bool Event_recorder::inject(Vm_state *vms)
{
  if (empty())
    return false;

  auto top = _queue.top();
  if (top->inject(vms))
    {
      _queue.pop();
      if (top->prio == Event_prio::Exception)
        {
          if (_queue.empty() || _queue.top()->prio != Event_prio::Exception)
            _has_exception = false;
        }
      else if (top->prio == Event_prio::Nmi)
        _has_nmi = false;
      else if (top->prio == Event_prio::Irq)
        _has_irq = false;

      // We have ownership. We have to free the memory!
      free_event(top);
      return true;
    }

  return false;
}

void Event_recorder::add(Event_record *event)
{
  if (event->prio == Event_prio::Exception)
    _has_exception = true;
  else if (event->prio == Event_prio::Nmi)
    {
      if (_has_nmi)
        return;
      else
        _has_nmi = true;
    }
  else if (event->prio == Event_prio::Irq)
    {
      if (_has_irq)
        return;
      else
        _has_irq = true;
    }

  _queue.push(std::move(event));
}

void Event_recorder::clear()
{
  while (!_queue.empty())
    {
      auto top = _queue.top();
      _queue.pop();
      // We have ownership. We have to free the memory!
      free_event(top);
    }

  _has_exception = false;
  _has_nmi = false;
  _has_irq = false;
}

bool Event_recorder::empty() const
{ return _queue.empty(); }

void Event_recorder::dump(unsigned vcpu_id) const
{
  static char const *Event_prio_names[Event_prio::Prio_max] = {
    "Abort",
    "Exception",
    "Sw_int1",
    "Sw_int3",
    "Sw_intO",
    "Sw_intN",
    "Bound",
    "Reset",
    "Machine_check",
    "Trap_task_switch",
    "Ext_hw_intervention",
    "Trap_dbg_except",
    "Nmi",
    "Interrupt",
    "Fault_dbg_except",
    "Fault_fetch_next_instr",
    "Fault_decode_next_instr",
  };

  if (_queue.empty())
    {
      Dbg().printf("[%3u] Ev_rec: No event recorded.\n", vcpu_id);
      return;
    }

  auto prio = _queue.top()->prio;
  char const *name = prio < Event_prio::Prio_max ? Event_prio_names[prio]
                                                 : "Index out of bounds";
  Dbg().printf("[%3u] Ev_rec: Top event has prio %i (%s); #events: %zu\n",
               vcpu_id, prio, name, _queue.size());
}

} // namespace Vmm
