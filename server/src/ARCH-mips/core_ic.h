/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>
#include <cstdio>
#include <mutex>

#include <l4/cxx/bitfield>

#include "irq.h"
#include "vcpu_ptr.h"

namespace Gic {

/**
 * Interrupt handler for core interrupts for a single VCPU.
 *
 * The Mips core interrupts are line-triggered and can be connected
 * to multiple devices. This is implemented by a pending counter for
 * each interrupt. Only connect stateful IRQ sinks to ensure the counting
 * is correct.
 *
 * Only handles the hardware interrupts 2 - 7.
 */
class Vcpu_ic : public Ic
{
  enum
  {
    Min_irq = 2,
    Max_irq = 7
  };

public:
  Vcpu_ic()
  : _cpu_irq(L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                          "allocate vcpu notification interrupt")),
    _irqvec(0)
  {
    for (size_t i = Min_irq; i <= Max_irq; ++i)
      _pending[i - Min_irq] = 0;

    L4Re::Env::env()->factory()->create(_cpu_irq.get());
  }

  void attach_cpu_thread(L4::Cap<L4::Thread> thread)
  { L4Re::chksys(_cpu_irq->bind_thread(thread, 0)); }

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override
  {}

  void set(unsigned irq) override
  {
    assert(Min_irq <= irq && irq <= Max_irq);
    std::lock_guard<std::mutex> lock(_lock);
    if (++_pending[irq - Min_irq] == 1)
      {
        _irqvec |= 1UL << (irq - Min_irq);
        _cpu_irq->trigger();
      }
  }

  void clear(unsigned irq) override
  {
    assert(Min_irq <= irq && irq <= Max_irq);
    std::lock_guard<std::mutex> lock(_lock);
    if (--_pending[irq - Min_irq] == 0)
      {
        _irqvec &= ~(1UL << (irq - Min_irq));
        _cpu_irq->trigger();
      }
  }

  void bind_irq_source(unsigned, cxx::Ref_ptr<Irq_source> const &) override
  {
    L4Re::chksys(-L4_ENOSYS, "unmask not supported for Core IC. "
                             "Use GIC for devices that require EOI via IC.");
  }

  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned) const override
  { return nullptr; }

  int dt_get_num_interrupts(Vdev::Dt_node const &node) override
  {
    int size;
    if (!node.get_prop<fdt32_t>("interrupts", &size))
      return 0;

    return size;
  }

  unsigned dt_get_interrupt(Vdev::Dt_node const &node, int irq) override
  {
    auto *prop = node.check_prop<fdt32_t>("interrupts", irq + 1);

    return fdt32_to_cpu(prop[irq]);
  }

  l4_uint32_t irq_vector()
  {
    std::lock_guard<std::mutex> lock(_lock);
    return _irqvec;
  }

  void show_state(FILE *f, Vmm::Vcpu_ptr vcpu)
  {
    auto *s = vcpu.state();
    s->update_state(L4_VM_MOD_STATUS);
    unsigned imask = s->g_status >> 8;
    unsigned ipending = s->g_cause >> 8;

    for (unsigned i = Min_irq; i <= Max_irq; ++i)
      fprintf(f, " Int %d: %d (HW: %s/%s)\n", i,
              _pending[i - Min_irq],
              imask & (1 << i) ? "on" : "off",
              ipending & (1 << i) ? "pending" : "low");
  }

private:
  L4Re::Util::Unique_cap<L4::Irq> _cpu_irq;
  /// Cached output pending array.
  l4_uint32_t _irqvec;
  /// Count for each interrupt the number of incomming sources.
  int _pending[Max_irq - Min_irq + 1];
  std::mutex _lock;
};

/**
 * Device for all core interrupts.
 *
 * This device is not an interrupt handler itself, it just holds
 * an array of core interrupt handlers, one for each core.
 */
class Mips_core_ic : public virtual Vdev::Dev_ref
{
  enum { Max_ics = 32 };

  struct Hw_int_reg
  {
    l4_umword_t raw;
    CXX_BITFIELD_MEMBER(10, 15, hw_ints, raw);

    Hw_int_reg(l4_umword_t r) : raw(r) {}
  };

public:
  Mips_core_ic()
  {
    // there always is an IC for CPU 0
    _core_ics[0] = Vdev::make_device<Vcpu_ic>();
  }

  virtual ~Mips_core_ic() = default;

  void create_ic(unsigned i, L4::Cap<L4::Thread> thread)
  {
    assert(i <= Max_ics);
    // start up one core IC per vcpu
    if (!_core_ics[i])
      _core_ics[i] = Vdev::make_device<Vcpu_ic>();
    _core_ics[i]->attach_cpu_thread(thread);
  }

  cxx::Ref_ptr<Vcpu_ic> get_ic(unsigned cpuid) const
  {
    assert(cpuid < Max_ics);
    return _core_ics[cpuid];
  }

  static bool has_pending(Vmm::Vcpu_ptr vcpu)
  {
    return Hw_int_reg(vcpu.state()->guest_ctl_2).hw_ints();
  }

  void update_vcpu(Vmm::Vcpu_ptr vcpu)
  {
    unsigned cpuid = vcpu.get_vcpu_id();

    assert(cpuid < Max_ics);
    assert(_core_ics[cpuid]);

    auto irqvec = _core_ics[cpuid]->irq_vector();

    Hw_int_reg *gc2 = (Hw_int_reg *) &vcpu.state()->guest_ctl_2;
    l4_uint32_t oldvec = gc2->hw_ints();

    if (oldvec == irqvec)
      return;

    gc2->hw_ints() = irqvec;
    vcpu.state()->set_modified(L4_VM_MOD_GUEST_CTL_2);
  }

  void show_state(FILE *f, Vmm::Vcpu_ptr vcpu)
  {
    unsigned cpuid = vcpu.get_vcpu_id();
    if (_core_ics[cpuid])
      _core_ics[cpuid]->show_state(f, vcpu);
  }

private:
  cxx::Ref_ptr<Vcpu_ic> _core_ics[Max_ics];
};

} // namespace
