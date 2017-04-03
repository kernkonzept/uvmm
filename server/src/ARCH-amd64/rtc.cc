/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "device_factory.h"
#include "guest.h"
#include "device.h"
#include "io_device.h"

namespace Vdev {

class Rtc : public Vmm::Io_device, public Vdev::Device
{
  void io_out(unsigned, Vmm::Mem_access::Width, l4_uint32_t) override {}

  void io_in(unsigned, Vmm::Mem_access::Width, l4_uint32_t *value) override
  { *value = 0; }

  // Device interface
  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override
  {}
};

} // namespace Vdev

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup const *devs,
                                    Vdev::Dt_node const &) override
  {
    auto dev = Vdev::make_device<Vdev::Rtc>();

    devs->vmm()->register_io_device(dev, 0x70, 0x2);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-rtc", nullptr, &f};

} // namespace
