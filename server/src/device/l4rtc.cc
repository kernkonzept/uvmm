/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */

/**
 * This driver retrieves wallclock time from the L4Re rtc server.
 *
 * It is optional and needs to be enabled in Makefile.config.
 *
 * Example device tree entry:
 *
 *      external_rtc {
 *          compatible = "l4rtc";
 *          l4vmm,rtccap = "rtc";
 *      };
 *
 * A capability with the name "rtc" needs to point to the rtc server.
 */
#include "rtc-hub.h"
#include "device_factory.h"
#include "device.h"

#include <l4/re/env>
#include <l4/rtc/rtc>

namespace Vdev {

class External_rtc:
  public Vdev::L4rtc_adapter,
  public Vdev::Device
{
  L4::Cap<L4rtc::Rtc> _rtc;

public:
  External_rtc(L4::Cap<L4rtc::Rtc> cap)
  : _rtc(cap)
  {
    L4rtc_hub::get()->register_adapter(this);
    if (_rtc->get_timer_offset(&_ns_offset))
      {
        warn().printf("Could not read time @rtc.\n");
        _ns_offset = 0;
      }
  }

  l4_uint64_t ns_since_epoch()
  {
    return _ns_offset + l4_kip_clock_ns(l4re_kip());
  }

  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "RTC"); }

private:
  // offset of kip_clock to epoch (wallclock time)
  l4_uint64_t _ns_offset;
};

}

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *,
                                    Vdev::Dt_node const &node) override
  {
    L4::Cap<L4rtc::Rtc> cap = Vdev::get_cap<L4rtc::Rtc>(node, "l4vmm,rtccap");
    if (!cap)
      {
        Vdev::External_rtc::warn().printf("l4vmm,rtccap not valid. Will not have wallclock time.\n");
        return nullptr;
      }

    auto dev = Vdev::make_device<Vdev::External_rtc>(cap);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"l4rtc", nullptr, &f};

} // namespace
