/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/env>
#include <l4/sys/scheduler>

#include "debug.h"
#include "device.h"
#include "cpu_dev.h"
#include "monitor/cpu_dev_array_cmd_handler.h"

namespace Vmm {

/**
 * Abstract CPU container.
 */
class Cpu_dev_array
: public virtual Vdev::Dev_ref,
  public Monitor::Cpu_dev_array_cmd_handler<Monitor::Enabled, Cpu_dev_array>
{
  friend Cpu_dev_array_cmd_handler<Monitor::Enabled, Cpu_dev_array>;

  /**
   * Helper class that distributes threads evenly to all available
   * physical CPUs.
   *
   * Exactly one VCPU is assigned per physical CPU. If more VCPUs
   * are requested, they remain disabled.
   */
  class Vcpu_placement
  {
  public:
    enum : unsigned { Invalid_id = ~0U };

    Vcpu_placement() : _next_id(0), _offset(0)
    {
      auto scheduler = L4Re::Env::env()->scheduler();
      _cs = l4_sched_cpu_set(_offset, 0);
      L4Re::chksys(scheduler->info(&_max_cpus, &_cs));
    }

    unsigned next_free()
    {
      if (_next_id > _max_cpus)
        return Invalid_id;

      auto scheduler = L4Re::Env::env()->scheduler();
      while (!(_cs.map & (1UL << _next_id)))
        {
          ++_next_id;
          if (_next_id > _max_cpus)
            return Invalid_id;
          l4_umword_t new_offset = _next_id / (sizeof(l4_umword_t) * 8);
          if (new_offset != _offset)
            {
              _offset = new_offset;
              _cs = l4_sched_cpu_set(_offset, 0);
              L4Re::chksys(scheduler->info(&_max_cpus, &_cs));
            }
        }

      unsigned ret = _next_id++;

      return ret;
    }

  private:
    l4_sched_cpu_set_t _cs;
    unsigned _next_id;
    l4_umword_t _offset;
    l4_umword_t _max_cpus;
  };

public:
  virtual ~Cpu_dev_array() = default;

  bool vcpu_exists(unsigned cpuid) const
  {
    assert(cpuid < Cpu_dev::Max_cpus);
    return !!_cpus[cpuid];
  }

  Vcpu_ptr vcpu(unsigned cpuid) const
  {
    assert(vcpu_exists(cpuid));
    return _cpus[cpuid]->vcpu();
  }

  cxx::Ref_ptr<Cpu_dev> cpu(unsigned cpuid) const
  {
    assert(vcpu_exists(cpuid));
    return _cpus[cpuid];
  }

  /// Return the maximum CPU id in use.
  unsigned max_cpuid() const
  {
    for (unsigned i = Cpu_dev::Max_cpus - 1; i > 0; --i)
      if (_cpus[i])
        return i;

    return 0;
  }

  /**
   * Add a CPU to the array.
   */
  cxx::Ref_ptr<Vdev::Device>
  create_vcpu(Vdev::Dt_node const *node);

  cxx::Ref_ptr<Cpu_dev> *begin() { return _cpus; }
  cxx::Ref_ptr<Cpu_dev> *end() { return _cpus + _ncpus; }

  unsigned capacity() const { return Cpu_dev::Max_cpus; }
  unsigned size() const { return _ncpus; }

protected:
  Vcpu_placement _placement;
  cxx::Ref_ptr<Cpu_dev> _cpus[Cpu_dev::Max_cpus];
  unsigned _ncpus = 0;
};

} // namespace
