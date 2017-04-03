/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>

namespace Vmm {

class Vm_state
{
public:
  virtual ~Vm_state() = 0;

  virtual void init_state() = 0;
  virtual void setup_protected_mode(l4_addr_t entry) = 0;

  virtual l4_umword_t ip() const = 0;
  virtual bool pf_write() const = 0;
  virtual l4_umword_t cr3() const = 0;
  virtual bool interrupts_enabled() const = 0;

  virtual void jump_instruction() = 0;
  virtual void inject_interrupt(unsigned vec) = 0;
  virtual void unhalt() = 0;

  virtual void disable_interrupt_window() = 0;
  virtual void enable_interrupt_window() = 0;

  virtual void dump_state() const = 0;
};

} // namespace Vmm

