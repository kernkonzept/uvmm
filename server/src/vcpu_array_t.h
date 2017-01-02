/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <pthread.h>
#include <pthread-l4.h>

#include <l4/re/env>
#include <l4/re/rm>
#include <l4/sys/scheduler>
#include <l4/sys/task>
#include <l4/sys/debugger.h>

#include "debug.h"
#include "device.h"
#include "vcpu.h"

namespace Vmm {

/**
 * Abstract CPU container.
 */
template <typename VCPU, unsigned SIZE>
class Vcpu_array_t : public virtual Vdev::Dev_ref
{
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
  /// Maximum number of supported CPUs.
  enum { Max_cpus = SIZE };

  /// pointer to startup code for VCPU thread
  typedef void *(*Vcpu_start_proc) (void *);

  Vcpu_array_t()
  {
    // Per default a single-core system is created.
    // Other CPUs can be added via the device tree configuration.
    // It also allows to configure a more specific CPU type.
    create_vcpu(0);
    assert(_cpus[0]);
  }

  virtual ~Vcpu_array_t() = default;

  bool vcpu_exists(unsigned cpuid) const
  {
    assert(cpuid < Max_cpus);
    return !!_cpus[cpuid];
  }

  Cpu vcpu(unsigned cpuid) const
  {
    assert(vcpu_exists(cpuid));
    return _cpus[cpuid]->vcpu();
  }

  /// Return the maximum CPU id in use.
  unsigned max_cpuid() const
  {
    for (unsigned i = Max_cpus - 1; i > 0; --i)
      if (_cpus[i])
        return i;

    return 0;
  }

  /**
   * Add a CPU to the array.
   *
   * If a CPU with the given ID already exists, then only the
   * type information is updated.
   */
  cxx::Ref_ptr<Vdev::Device> create_vcpu(unsigned id,
                                         char const *compatible = nullptr)
  {
    if (id >= Max_cpus)
      return nullptr;

    if (!_cpus[id])
      {
        unsigned cpu_mask = _placement.next_free();

        if (cpu_mask == Vcpu_placement::Invalid_id)
          return nullptr;

        auto *e = L4Re::Env::env();
        l4_addr_t vcpu_addr = 0x10000000;

        L4Re::chksys(e->rm()->reserve_area(&vcpu_addr, L4_PAGESIZE,
                                           L4Re::Rm::Search_addr));
        L4Re::chksys(e->task()->add_ku_mem(
                       l4_fpage(vcpu_addr, L4_PAGESHIFT, L4_FPAGE_RWX)),
                     "kumem alloc");

        Dbg(Dbg::Cpu, Dbg::Info).printf("Created VCPU %d @ %lx\n", id, vcpu_addr);

        _cpus[id] = Vdev::make_device<VCPU>(id, vcpu_addr, cpu_mask);
      }

    if (compatible)
      _cpus[id]->set_proc_type(compatible);

    return _cpus[id];
  }

  /**
   * Create a thread for all vcpus except the initial one.
   *
   * Vcpus are scheduled round-robin on the available CPUs.
   */
  void powerup_cpus(Vcpu_start_proc proc)
  {
    pthread_attr_t pattr;
    L4Re::chksys(pthread_attr_init(&pattr));
    pattr.create_flags |= PTHREAD_L4_ATTR_NO_START;

    schedule_vcpu(0, pthread_self());
    char vcpu_name[7];
    strcpy(vcpu_name, "vcpu00");
    l4_debugger_set_object_name(pthread_l4_cap(pthread_self()), vcpu_name);

    for (unsigned i = 1; i < Max_cpus; ++i)
      {
        if (!_cpus[i])
          continue;

        pthread_t thread;
        auto r = pthread_create(&thread, &pattr, proc,
                                (void *) *(_cpus[i]->vcpu()));
        if (i < 100)
          {
            sprintf(vcpu_name, "vcpu%02d", i);
            l4_debugger_set_object_name(pthread_l4_cap(thread), vcpu_name);
          }
        if (r != 0)
          L4Re::chksys(-L4_ENOMEM, "Cannot start vcpu thread");

        schedule_vcpu(i, thread);
      }

    L4Re::chksys(pthread_attr_destroy(&pattr));
  }

private:
  void schedule_vcpu(unsigned id, pthread_t thread)
  {
    assert(_cpus[id]);
    l4_sched_param_t sp = l4_sched_param(2);
    sp.affinity = l4_sched_cpu_set(_cpus[id]->sched_cpu(), 0);

    auto sched = L4Re::Env::env()->scheduler();
    L4Re::chksys(sched->run_thread(Pthread::L4::cap(thread), sp));
  }

protected:
  Vcpu_placement _placement;
  cxx::Ref_ptr<VCPU> _cpus[Max_cpus];

};

} // namespace
