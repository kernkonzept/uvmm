/*
 * Copyright (C) 2026 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "debug.h"
#include "device.h"
#include "mmio-mock-dev.h"
#include "device_factory.h"
#include "guest.h"

namespace {

using namespace Vdev;
static Dbg warn(Dbg::Dev, Dbg::Warn, "mmio-mock");

class F : public Factory
{
public:
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    l4_uint64_t regbase, size;
    if (node.get_reg_val(0, &regbase, &size) < 0)
      return nullptr;

    printf("Create MMIO mock device for [0x%llx, 0x%llx]\n",
           regbase, regbase + size - 1);

    auto dev = Vdev::make_device<Mmio_mock_dev>(regbase, size);
    devs->vmm()->add_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(regbase), size,
                                                 Vmm::Region_type::Virtual),
                                 dev);

    return dev;
  }
};

static F f;
static Device_type t = { "l4vmm,mock-mmio", nullptr, &f };
}
