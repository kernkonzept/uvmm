/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "legacy_pic.h"
#include "device_factory.h"
#include "guest.h"

namespace
{
  struct F : Vdev::Factory
  {
    cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                      Vdev::Dt_node const &node) override
    {
      auto msi_distr = devs->get_or_create_mc_dev(node);
      Dbg().printf("PIC found MSI ctrl %p\n", msi_distr.get());

      auto dev = Vdev::make_device<Vdev::Legacy_pic>(msi_distr);

      auto *vmm = devs->vmm();
      vmm->add_io_device(Vmm::Io_region(0x20, 0x21, Vmm::Region_type::Virtual),
                         dev->master());
      vmm->add_io_device(Vmm::Io_region(0xA0, 0xA1, Vmm::Region_type::Virtual),
                         dev->slave());

      return dev;
    }
  }; // struct F

  static F f;
  static Vdev::Device_type t = {"virt-i8259-pic", nullptr, &f};
} // namespace
