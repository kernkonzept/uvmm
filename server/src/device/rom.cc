/*
 * Copyright (C) 2022-2024 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "debug.h"
#include "device_factory.h"
#include "guest.h"

namespace {

/**
 * Device for adding dataspaces readonly to the guest.
 *
 * A device tree entry needs to look like this:
 *
 * \code{.dtb}
 *   rom@ffc84000 {
 *       compatible = "l4vmm,rom";
 *       reg = <0x0 0xffc84000 0x0 0x37c000>;
 *       l4vmm,dscap = "bios";
 *   };
 * \endcode
 *
 * l4vmm,dscap is mandatory and points to the dataspace cap to use.
 */
class Rom
: public Vdev::Device
{};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto warn = Dbg(Dbg::Dev, Dbg::Warn, "ROM");
    auto dscap = Vdev::get_cap<L4Re::Dataspace>(node, "l4vmm,dscap");
    if (!dscap)
      {
        warn.printf("Missing 'l4vmm,dscap' property!\n");
        return nullptr;
      }

    l4_uint64_t base, size;
    int res = node.get_reg_val(0, &base, &size);
    if (res < 0)
      {
        warn.printf("Missing 'reg' property for node %s\n", node.get_name());
        return nullptr;
      }

    if (size > dscap->size())
      {
        warn.printf("Dataspace smaller than reg window. Unsupported.\n");
        return nullptr;
      }

    devs->ram()->add_memory_region(dscap, Vmm::Guest_addr(base), 0, size,
                                   devs->vmm()->memmap(), L4Re::Rm::F::RX);

    return Vdev::make_device<Rom>();
  }
};

}

static F f;
static Vdev::Device_type t = { "l4vmm,rom", nullptr, &f };
