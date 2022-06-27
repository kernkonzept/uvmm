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

  virtual bool read_msr(unsigned msr, l4_uint64_t *value) const = 0;
  virtual bool write_msr(unsigned msr, l4_uint64_t value) = 0;
};

} // namespace Vmm

