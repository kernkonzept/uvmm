/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2021 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include "gic_cpu.h"
#include "gic_dist.h"
#include "mmio_device.h"

namespace Gic {

template<typename GIC_IMPL, bool AFF_ROUTING>
class Dist_mixin
: public Dist<AFF_ROUTING>,
  public Vmm::Mmio_device_t<GIC_IMPL>
{
private:
  GIC_IMPL *self() { return static_cast<GIC_IMPL *>(this); }
  GIC_IMPL const *self() const { return static_cast<GIC_IMPL const *>(this); }

public:
  Dist_mixin(unsigned tnlines, unsigned char cpus)
  : Dist<AFF_ROUTING>(tnlines, cpus)
  {}

  void inject_irq_local(Irq &irq, Cpu *current_cpu)
  {
    if (irq.pending(true))
      current_cpu->inject<typename GIC_IMPL::Cpu_if>(irq);
  }

  void inject_irq(Irq &irq, Cpu *current_cpu)
  {
    Vcpu_handler *dest_cpu = irq.pending(true);
    if (dest_cpu)
      {
        if (current_cpu == dest_cpu)
          current_cpu->inject<typename GIC_IMPL::Cpu_if>(irq);
        else
          dest_cpu->notify_irq();
      }
  }

  void set(unsigned irq) override
  {
    Cpu *current_cpu = this->_cpu[vmm_current_cpu_id].get();
    if (irq < Cpu::Num_local)
      inject_irq_local(current_cpu->local_irq(irq), current_cpu);
    else if (irq < Cpu::Lpi_base)
      inject_irq(this->spi(irq - Cpu::Num_local), current_cpu); // SPI
    else
      inject_irq(this->lpi(irq - Cpu::Lpi_base), current_cpu); // LPI
  }

  bool schedule_irqs(unsigned current_cpu) override
  {
    using Cpu_if = typename GIC_IMPL::Cpu_if;

    assert (current_cpu < this->_cpu.size());
    Cpu *c = this->_cpu[current_cpu].get();

    c->handle_eois<Cpu_if>();
    c->handle_ipis<GIC_IMPL>();
    c->handle_migrations();

    if (!(this->ctlr & 3U))
      return false;

    unsigned pmask = this->_prio_mask;

    for (;;)
      {
        unsigned empty_lr = c->get_empty_lr();

        if (!empty_lr)
          return true;

        Irq *irq = c->take_pending_irq(pmask);
        if (!irq)
          return c->pending_irqs();

        if (0)
          this->trace().printf("Inject: irq=%u on cpu=%d... ",
                               irq->id(), current_cpu);
        c->add_pending_irq<typename GIC_IMPL::Cpu_if>(empty_lr - 1, *irq);
      }
  }

  void handle_maintenance_irq(unsigned current_cpu) override
  {
    assert (current_cpu < this->_cpu.size());
    Cpu *c = this->_cpu[current_cpu].get();
    auto misr = c->misr();
    auto hcr = c->hcr();
    if (misr.grp0_e())
      {
        hcr.vgrp0_eie() = 0;
        hcr.vgrp0_die() = 1;
      }

    if (misr.grp0_d())
      {
        hcr.vgrp0_eie() = 1;
        hcr.vgrp0_die() = 0;
      }

    if (misr.grp1_e())
      {
        hcr.vgrp1_eie() = 0;
        hcr.vgrp1_die() = 1;
      }

    if (misr.grp1_d())
      {
        hcr.vgrp1_eie() = 1;
        hcr.vgrp1_die() = 0;
      }

    c->write_hcr(hcr);

    c->handle_maintenance_irq<typename GIC_IMPL::Cpu_if>();
  }

  void cpu_online(Vmm::Vcpu_ptr vcpu) override
  {
    unsigned current_cpu = vcpu.get_vcpu_id();
    Cpu *c = this->_cpu[current_cpu].get();
    assert(!c->online());
    c->online(vcpu, current_cpu == 0);
    this->retarget_spis();
  }

  void cpu_offline(Vmm::Vcpu_ptr vcpu) override
  {
    unsigned current_cpu = vcpu.get_vcpu_id();
    Cpu *c = this->_cpu[current_cpu].get();

    assert(c->online());
    c->offline(this->_cpu[0]->vcpu());
    this->retarget_spis();
  }
};

}
