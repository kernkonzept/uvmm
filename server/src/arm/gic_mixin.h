/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include "gic.h"

namespace Gic {

template<typename GIC_IMPL>
class Dist_mixin
: public Dist,
  public Vmm::Mmio_device_t<GIC_IMPL>
{
private:
  GIC_IMPL *self() { return static_cast<GIC_IMPL *>(this); }
  GIC_IMPL const *self() const { return static_cast<GIC_IMPL const *>(this); }

  int find_pending_spi_intid(unsigned pmask, unsigned target, Irq *irq)
  {
    int x = self()->find_pending_spi(pmask, target, irq);
    if (x >= 0)
      return x + Num_local;

    return -1;
  }

public:
  Dist_mixin(unsigned tnlines, unsigned char cpus)
  : Dist(tnlines, cpus)
  {}

  bool schedule_irqs(unsigned current_cpu) override
  {
    using Cpu_if = typename GIC_IMPL::Cpu_if;

    assert (current_cpu < _cpu.size());
    Cpu *c = _cpu[current_cpu].get();

    c->handle_eois<Cpu_if>();
    c->handle_ipis<GIC_IMPL>();

    unsigned pmask = _prio_mask;

    for (;;)
      {
        unsigned empty_lr = c->get_empty_lr();

        if (!empty_lr)
          return true;

        Irq irq;
        int irq_id = c->find_pending_irq(pmask, &irq);
        if (irq_id < 0)
          irq_id = find_pending_spi_intid(pmask, current_cpu, &irq);

        if (irq_id < 0)
          return c->pending_irqs();

        if (0)
          gicd_trace.printf("Try to inject: irq=%d on cpu=%d... ",
                            irq_id, current_cpu);
        bool ok = c->add_pending_irq<Cpu_if>(empty_lr - 1, irq, irq_id);
        if (0)
          gicd_trace.printf("%s\n", ok ? "OK" : "FAILED");
      }
  }

  void handle_maintenance_irq(unsigned current_cpu) override
  {
    assert (current_cpu < _cpu.size());
    Cpu *c = _cpu[current_cpu].get();
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

    self()->update_gicc_state(misr, current_cpu);

    c->write_hcr(hcr);

    c->handle_maintenance_irq<typename GIC_IMPL::Cpu_if>(current_cpu);
  }
};

}
