/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/env>
#include <l4/sys/scheduler>
#include <vector>

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
  typedef std::vector<cxx::Ref_ptr<Cpu_dev>> Cpu_dev_vector;

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
      update_cpu_set(0);
    }

    unsigned next_free()
    {
      if (_next_id >= _max_cpus)
        return Invalid_id;

      while (true)
        {
          unsigned next_id_offset = _next_id % _bits_in_cpu_map;
          if ((_next_id - _offset) >= _bits_in_cpu_map)
            update_cpu_set(_next_id - next_id_offset);

          if (_cs.map & (1UL << next_id_offset))
            return _next_id++;

          ++_next_id;

          if (_next_id >= _max_cpus)
            return Invalid_id;
        }

    }

  private:
    void update_cpu_set(l4_umword_t new_offset)
    {
      _offset = new_offset;
      _cs = l4_sched_cpu_set(_offset, 0);

      auto scheduler = L4Re::Env::env()->scheduler();
      L4Re::chksys(scheduler->info(&_max_cpus, &_cs),
                   "Get scheduler info for next batch of cores.");
    }

    l4_sched_cpu_set_t _cs;
    unsigned _next_id;
    unsigned const _bits_in_cpu_map = sizeof(_cs.map) * 8;
    l4_umword_t _offset;
    l4_umword_t _max_cpus;
  };

public:
  virtual ~Cpu_dev_array() = default;

  bool vcpu_exists(unsigned cpuid) const
  {
    return cpuid < _cpus.size() && !!_cpus[cpuid];
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
  { return _cpus.size() - 1; }

  /**
   * Add a CPU to the array.
   */
  cxx::Ref_ptr<Vdev::Device>
  create_vcpu(Vdev::Dt_node const *node);

  Cpu_dev_vector::iterator begin() { return _cpus.begin(); }
  Cpu_dev_vector::const_iterator begin() const { return _cpus.begin(); }

  Cpu_dev_vector::iterator end() { return _cpus.end(); }
  Cpu_dev_vector::const_iterator end() const { return _cpus.end(); }

  unsigned size() const { return _cpus.size(); }

protected:
  Vcpu_placement _placement;
  Cpu_dev_vector _cpus;
};

} // namespace
