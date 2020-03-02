/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
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
      vmm->register_io_device(Vmm::Io_region(0x20, 0x21,
                                             Vmm::Region_type::Virtual),
                              dev->master());
      vmm->register_io_device(Vmm::Io_region(0xA0, 0xA1,
                                             Vmm::Region_type::Virtual),
                              dev->slave());

      return dev;
    }
  }; // struct F

  static F f;
  static Vdev::Device_type t = {"virt-i8259-pic", nullptr, &f};
} // namespace
