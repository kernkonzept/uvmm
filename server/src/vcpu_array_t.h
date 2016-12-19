/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/rm>
#include <l4/sys/task>

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
public:
  /// Maximum number of supported CPUs.
  enum { Max_cpus = SIZE };

  Vcpu_array_t()
  {
    // Per default a single-core system is created.
    // Other CPUs can be added via the device tree configuration.
    // It also allows to configure a more specific CPU type.
    create_vcpu(0);
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
        auto *e = L4Re::Env::env();
        l4_addr_t vcpu_addr = 0x10000000;

        L4Re::chksys(e->rm()->reserve_area(&vcpu_addr, L4_PAGESIZE,
                                           L4Re::Rm::Search_addr));
        L4Re::chksys(e->task()->add_ku_mem(
                       l4_fpage(vcpu_addr, L4_PAGESHIFT, L4_FPAGE_RWX)),
                     "kumem alloc");

        Dbg(Dbg::Cpu, Dbg::Info).printf("Created VCPU %d @ %lx\n", id, vcpu_addr);

        _cpus[id] = Vdev::make_device<VCPU>(id, vcpu_addr);
      }

    if (compatible)
      _cpus[id]->set_proc_type(compatible);

    return _cpus[id];
  }

protected:
  cxx::Ref_ptr<VCPU> _cpus[Max_cpus];

};

} // namespace
