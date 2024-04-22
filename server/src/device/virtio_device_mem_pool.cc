/*
 * Copyright (C) 2024 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "device_factory.h"
#include "virtio_device_mem_pool.h"

namespace {

using namespace Vdev;

class F : public Factory
{
public:
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    Dbg info(Dbg::Dev, Dbg::Info, "viodev-mp");

    l4_uint64_t phys, size;
    if (node.get_reg_val(0, &phys, &size) < 0)
      L4Re::throw_error(-L4_EINVAL, "reg property not found or invalid");

    auto c = Vdev::make_device<Virtio_device_mem_pool>(devs, phys, size);

    info.printf("%s: virtio device memory pool registered [0x%llx:0x%llx]\n",
                node.get_name(), phys, size);

    return c;
  }
};

static F f;
static Device_type t1 = { "l4vmm,mempool", nullptr, &f };

}
