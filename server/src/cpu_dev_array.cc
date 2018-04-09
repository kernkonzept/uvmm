/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cpu_dev_array.h>

namespace Vmm {

cxx::Ref_ptr<Vdev::Device>
Cpu_dev_array::create_vcpu(Vdev::Dt_node const *node)
{
  l4_int32_t prop_val = 0;
  if (node)
    {
      auto *prop = node->get_prop<fdt32_t>("reg", nullptr);
      if (!prop)
        {
          Err().printf("Cpu node '%s' has missing reg property. Ignored.\n",
                       node->get_name());
          return nullptr;
        }
      prop_val = fdt32_to_cpu(*prop);
    }

  unsigned id = Cpu_dev::dtid_to_cpuid(prop_val);
  if (id >= Max_cpus)
    return nullptr;

  if (_cpus[id])
    {
      Dbg(Dbg::Cpu, Dbg::Warn).printf("Duplicate definitions for Cpu%d (%x)\n",
                                      id, prop_val);
      return _cpus[id];
    }

  unsigned cpu_mask = _placement.next_free();
  if (cpu_mask == Vcpu_placement::Invalid_id)
    return nullptr;

  _cpus[id] = Vdev::make_device<Cpu_dev>(id, cpu_mask, node);

  return _cpus[id];
}

void
Cpu_dev_array::show_state_registers(FILE *f)
{
  for (int i = 0; i < Max_cpus; ++i)
    {
      if (!_cpus[i])
        continue;

      // if (i != current_cpu)
      //  interrupt_vcpu(i);

      fprintf(f, "CPU %d\n", i);
      _cpus[i]->show_state_registers(f);
    }
}

}
