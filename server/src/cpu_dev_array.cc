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

static
unsigned get_dt_cpuid(Vdev::Dt_node const *node)
{
  // fallback to 0 if do DT node given
  if (!node)
    return Cpu_dev::dtid_to_cpuid(0);

  auto *prop = node->get_prop<fdt32_t>("reg", nullptr);
  if (!prop)
    {
      Err().printf("Cpu node '%s' has missing reg property. Ignored.\n",
                   node->get_name());
      return ~0u;
    }

  return Cpu_dev::dtid_to_cpuid(fdt32_to_cpu(*prop));
}

cxx::Ref_ptr<Vdev::Device>
Cpu_dev_array::create_vcpu(Vdev::Dt_node const *node)
{
  unsigned id = ~0u;
  if (Cpu_dev::has_fixed_dt_mapping())
    id = get_dt_cpuid(node);
  else if (_ncpus < capacity())
    id = _ncpus++;

  if (id >= capacity())
    {
      Err().printf("Too many virtual CPUs. Ignored.\n");
      return nullptr;
    }

  if (_cpus[id])
    {
      Dbg(Dbg::Cpu, Dbg::Warn)
        .printf("Duplicate definitions for Cpu%d\n", id);

      return _cpus[id];
    }

  if (id >= _ncpus)
    _ncpus = id + 1;

  unsigned cpu_mask = _placement.next_free();
  if (cpu_mask == Vcpu_placement::Invalid_id)
    return nullptr;

  _cpus[id] = Vdev::make_device<Cpu_dev>(id, cpu_mask, node);

  return _cpus[id];
}

}
