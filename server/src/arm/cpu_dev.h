/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "generic_cpu_dev.h"

#include <cstdio>

namespace Vmm {

class Cpu_dev : public Generic_cpu_dev
{
public:
  Cpu_dev(unsigned idx, unsigned phys_id)
  : Generic_cpu_dev(idx, phys_id)
  {}

  void set_proc_type(char const *) {}
  void show_state_registers(FILE *f);
  void reset() override {}
};

}

