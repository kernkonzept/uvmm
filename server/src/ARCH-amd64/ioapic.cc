/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "device_factory.h"
#include "guest.h"
#include "ioapic.h"

namespace {

  struct F : Vdev::Factory
  {
    cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                      Vdev::Dt_node const &node) override
    {
      auto msi_distr = devs->get_or_create_mc_dev(node);
      auto io_apic = Vdev::make_device<Gic::Io_apic>(msi_distr);
      devs->vmm()->add_mmio_device(io_apic->mmio_region(), io_apic);
      return io_apic;
    }
  };

  static F f;
  static Vdev::Device_type d = {"intel,ioapic", nullptr, &f};

}
