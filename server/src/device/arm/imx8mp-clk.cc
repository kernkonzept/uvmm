/*
 * Copyright (C) 2026 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/re/mmio_space>
#include <l4/re/env>

#include "debug.h"
#include "device.h"
#include "mmio_space_handler.h"
#include "device_factory.h"
#include "guest.h"

namespace {

using namespace Vdev;
static Dbg warn(Dbg::Dev, Dbg::Warn, "imx8-clk");

/**
 * Device to forward MMIO access to a imx8mp clock device to a muxer service.
 *
 * This converts the accesses to the imx8mp clock MMIO ranges to L4::Mmio_space
 * and calls the connected imx8mp-clock-muxer.
 * The intention is to extend the compatible of the clock node(s) in the
 * original linux device tree.
 * Just a single MMIO range is parsed from the reg-entry and the connected
 * muxer get's the full mapped address, not just the offset into the MMIO
 * space.
 *
 * Expects a named capability called `clks`, connecting it to the
 * imx8mp-clock-muxer.
 *
 * \code{.dtb}
 *   clock-controller@30380000 {
 *       compatible = "fsl,imx8mp-ccm", "l4vmm,imx8-clk";
 *       reg = <0x30380000 0x10000>;
 *       [...]
 *   };
 * \endcode
 */
class Imx8mp_clk_handler : public Mmio_space_handler, public Device
{
public:
  using Mmio_space_handler::Mmio_space_handler;

  char const *dev_name() const override { return "Imx8mp_clk_handler"; }
};

class F : public Factory
{
public:
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    l4_uint64_t regbase, size;
    if (node.get_reg_val(0, &regbase, &size) < 0)
      return nullptr;

    warn.printf("Create imx8-clk device for [0x%llx, 0x%llx]\n", regbase,
                regbase + size - 1);

    auto clk_drv = L4Re::Env::env()->get_cap<L4Re::Mmio_space>("clks");
    // pass in regbase as offset to forward the full MMIO address
    auto dev = Vdev::make_device<Imx8mp_clk_handler>(clk_drv, 0, size, regbase);
    devs->vmm()->add_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(regbase), size,
                                                 Vmm::Region_type::Vbus),
                                 dev);

    return dev;
  }
};

static F f;
static Device_type t = { "l4vmm,imx8-clk", nullptr, &f };
}
