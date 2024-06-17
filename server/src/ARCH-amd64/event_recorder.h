/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once
#include "event_record.h"
#include "vm_state.h"

#include <vector>
#include <queue>
#include <cassert>


namespace Vmm {

/// Recorder of all events for a core.
class Event_recorder
{
public:
  ~Event_recorder() { clear(); }

  /**
   * Inject highest priority event.
   *
   * \retval true   Event injected.
   * \retval false  No event to inject or can't inject pending event.
   */
  bool inject(Vm_state *vms);

  /**
   * Record an event.
   *
   * \note Pending interrupts are recorded as placeholder item such that the
   *       caller knows the query the local APIC. NMI and IRQs are just
   *       recorded once.
   *
   * \post Ownership moves to `Event_recorder`.
   */
  void add(Event_record *event);

  /// Clears all recorded events.
  void clear();
  /// True, iff no event recorded.
  bool empty() const;
  /// FIXME for MSR interface lacking return value tristate.
  bool has_exception() const { return _has_exception; }
  /// true, iff IRQ event already recorded
  bool has_nmi() const { return _has_nmi; }
  /// true, iff IRQ event already recorded
  bool has_irq() const { return _has_irq; }

  /// debugging aid
  void dump(unsigned vcpu_id) const;

  /// Create an Event instance and record it.
  template <typename T, typename... ARGS>
  void make_add_event(ARGS... args)
  { add(new T(std::forward<ARGS>(args)...)); }

private:
  using Qtype = Event_record *;

  struct QGreater
  {
    bool operator()(Qtype const &item1, Qtype const &item2) const
    { return *item1 > *item2; }
  };

  std::priority_queue<Qtype, std::vector<Qtype>, QGreater> _queue;
  bool _has_exception = false;
  bool _has_nmi = false;
  bool _has_irq = false;
};

/// Interface to get the event recorder for a specific core.
struct Event_recorders
{
  virtual Event_recorder *recorder(unsigned num) = 0;
};

/**
 * Management entity for one `Event_recorder` per core.
 */
class Event_recorder_array : public Event_recorders
{
public:
  virtual ~Event_recorder_array() = default;

  void init(unsigned size)
  { _recorders.resize(size); }

  Event_recorder *recorder(unsigned num) override
  {
    assert(num < _recorders.size());
    return &_recorders[num];
  }

private:
  std::vector<Event_recorder> _recorders;
};

} // namespace Vmm
