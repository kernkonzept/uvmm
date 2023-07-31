/*
 * Copyright (C) 2017-2019, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/cxx/bitfield>

namespace Vmm {

/// Abstraction of the VMX and SVM event injection format.
struct Injection_event
{
  l4_uint64_t raw = 0;
  CXX_BITFIELD_MEMBER(0, 31, event, raw);
  CXX_BITFIELD_MEMBER(32, 63, error, raw);
  // SVM and VMX both use the same bit encoding in the lower 11 bits.
  CXX_BITFIELD_MEMBER(0, 7, vector, raw);
  CXX_BITFIELD_MEMBER(8, 10, type, raw);
  CXX_BITFIELD_MEMBER(11, 11, error_valid, raw);
  // SVM and VMX both use bit 31 to indicate validity of the value.
  CXX_BITFIELD_MEMBER(31, 31, valid, raw);

  Injection_event(l4_uint32_t ev, l4_uint32_t err)
  {
    event() = ev;
    error() = err;
  }

  Injection_event(unsigned char v, unsigned char t, bool err_valid = false,
                  l4_uint32_t err_code = 0)
  {
    vector() = v;
    type() = t;
    error_valid() = err_valid;
    error() = err_code;
    valid() = 1;
  }

  explicit Injection_event(l4_uint64_t val) : raw(val) {}
};

class Event_recorder;

class Vm_state
{
public:
  enum class Type { Vmx, Svm };

  virtual ~Vm_state() = 0;

  virtual Type type() const = 0;

  virtual void init_state() = 0;
  virtual void setup_linux_protected_mode(l4_addr_t entry) = 0;
  virtual void setup_real_mode(l4_addr_t entry) = 0;

  virtual l4_umword_t ip() const = 0;
  virtual l4_umword_t sp() const = 0;
  virtual bool pf_write() const = 0;
  virtual l4_umword_t cr3() const = 0;
  virtual l4_uint64_t xcr0() const = 0;

  virtual bool read_msr(unsigned msr, l4_uint64_t *value) const = 0;
  virtual bool write_msr(unsigned msr, l4_uint64_t value, Event_recorder *ev_rec) = 0;

  virtual Injection_event pending_event_injection() = 0;
  virtual void inject_event(Injection_event const &ev) = 0;

  virtual bool can_inject_nmi() const = 0;
  virtual bool can_inject_interrupt() const = 0;
  virtual void disable_interrupt_window() = 0;
  virtual void enable_interrupt_window() = 0;
  virtual void disable_nmi_window() = 0;
  virtual void enable_nmi_window() = 0;

  // must only be called once per VM entry
  virtual void advance_entry_ip(unsigned bytes) = 0;
};

} // namespace Vmm

