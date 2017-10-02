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
  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *)
  : Generic_cpu_dev(idx, phys_id)
  {}

  void show_state_registers(FILE *f);
  void reset() override {}

  /**
   * Translate a device tree "reg" value to an internally usable CPU id.
   *
   * For most architectures this is NOP, but some archictures like ARM
   * might encode topology information into this value, which needs to
   * be translated.
   */
  static unsigned dtid_to_cpuid(l4_int32_t prop_val)
  { return prop_val & 0xf; }
};

}
