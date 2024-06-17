/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include "vm_state.h"

namespace Vmm {

/**
 * Event priority order
 *
 * The priortiy is specified in the Intel SDM 12/2022 Vol 3
 * Section 6.9 "Prioritization of Concurrent Events".
 */
enum Event_prio : char
{
  // on instruction events
  Abort = 0,
  Exception,
  Sw_int1,
  Sw_int3,
  Sw_intO,
  Sw_intN,
  Bound,
  // potentially concurrent events raised on instructions boundaries.
  Reset,
  Machine_check,
  Trap_task_switch,
  Ext_hw_intervention,
  Trap_dbg_except,
  Nmi,
  Irq,
  Fault_dbg_except,
  Fault_fetch_next_instr,
  Fault_decode_next_instr,

  Prio_max // must be last
};

/**
 *  Single event record, e.g. for an event raised by hardware.
 */
struct Event_record
{
  explicit Event_record(Event_prio p) : prio(p) {}

  virtual ~Event_record() = default;

  virtual bool inject(Vm_state *vms) = 0;

  constexpr bool operator < (Event_record const &o) const
  { return prio < o.prio; }

  constexpr bool operator > (Event_record const &o) const
  { return prio > o.prio; }

  constexpr bool operator == (Event_record const &o) const
  { return prio == o.prio; }

  Event_prio const prio;        ///< Type of the Event_record
};

/**
 * Exception event record.
 */
struct Event_exc : Event_record
{
  enum : unsigned { Invalid_error = ~0U };

  explicit Event_exc(Event_prio p, unsigned ev_num)
  : Event_record(p), ev_num(ev_num)
  {}

  Event_exc(Event_prio p, unsigned ev_num, unsigned e_val)
  : Event_record(p), ev_num(ev_num), error_val(e_val)
  {}

  bool inject(Vm_state *vm) override;

  unsigned ev_num;                     ///< Event number to inject
  unsigned error_val = Invalid_error;  ///< Error value to push on the stack
};

struct Real_mode_exc : Event_record
{
  explicit Real_mode_exc(Event_prio p, unsigned ev_num)
  : Event_record(p), ev_num(ev_num)
  {}

  bool inject(Vm_state *vm) override;

  unsigned ev_num;              ///< Event number to inject
};

/**
 * Generic software exception/interrupt event to inject into the guest.
 *
 * \tparam TYPE  Event type to use in injection.
 */
template <l4_uint8_t TYPE>
struct Event_sw_generic : Event_record
{
  Event_sw_generic(Event_prio p, unsigned ev_num, unsigned insn_len)
  : Event_record(p), ev_num(ev_num), instruction_len(insn_len)
  {}

  bool inject(Vm_state *vm) override
  {
    vm->inject_event(Injection_event(ev_num, TYPE, false));
    if (vm->type() == Vm_state::Type::Vmx)
      vm->advance_entry_ip(instruction_len);

    return true;
  }

  unsigned ev_num;              ///< Event number to inject
  unsigned instruction_len;     ///< Bytes to advance IP
};

} // namespace Vmm
