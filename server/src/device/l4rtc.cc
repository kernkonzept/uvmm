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
 * A capability with the name "rtc" needs to point to the rtc server. In the
 * event of the guest programming the rtc, the device model will also try to
 * set the time at the rtc server. The "rtc" cap requires 'write' permission
 * for this operation. Conversely, if the rtc server has a new wallclock time,
 * it notifies its clients. Uvmm will react to this notification by retrieving
 * the new wallclock time. There is no way to inform the guest, however.
 */
#include "rtc-hub.h"
#include "device_factory.h"
#include "device.h"
#include "guest.h"

#include <l4/cxx/ipc_server>
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <l4/rtc/rtc>

namespace Vdev {

class External_rtc:
  public Vdev::L4rtc_adapter,
  public Vdev::Device,
  public L4::Irqep_t<External_rtc>
{
  L4::Cap<L4rtc::Rtc> _rtc;
  L4::Registry_iface *_registry;

public:
  External_rtc(L4::Cap<L4rtc::Rtc> cap, L4::Registry_iface *registry)
  : _rtc(cap), _registry(registry)
  {
    L4rtc_hub::register_adapter(this);
    if (_rtc->get_timer_offset(&_ns_offset))
      {
        warn().printf("Could not read time from RTC server.\n");
        _ns_offset = 0;
      }

    auto irq = L4Re::Util::make_unique_cap<L4::Irq>();
    if (!irq)
      {
        warn().printf("Could not allocate capability for "
                      "notification IRQ from RTC server. "
                      "Uvmm will not be notified of new time values.\n");
        return;
      }
    if (l4_error(L4Re::Env::env()->factory()->create<L4::Irq>(irq.get())))
      {
        warn().printf("Could not create IRQ object for notifications from "
                      "RTC server. "
                      "Uvmm will not be notified of new time values.\n");
        return;
      }
    if (l4_error(_rtc->bind(0, irq.get())))
      {
        warn().printf("Could not bind IRQ to RTC server. "
                      "Uvmm will not be notified of new time values.\n");
        return;
      }

    auto res = registry->register_obj(this, irq.get());
    if (!res)
      {
        warn().printf("Could not register RTC IRQ handler. "
                      "Uvmm will not be notified of new time values.\n");
        _rtc->unbind(0, irq.get());
        return;
      }

    _irq = std::move(irq);
  }

  ~External_rtc()
  {
    _rtc->unbind(0, _irq.get());
    _registry->unregister_obj(this);
    // Remove a potential reference to this object.
    L4rtc_hub::invalidate();
  }

  l4_uint64_t ns_since_epoch() override
  {
    return _ns_offset + l4_kip_clock_ns(l4re_kip());
  }

  void set_ns_since_epoch(l4_uint64_t ns_offset) override
  {
    int err;
    _ns_offset = ns_offset - l4_kip_clock_ns(l4re_kip());
    if ((err = _rtc->set_timer_offset(_ns_offset)))
      warn().printf("Failed at setting the time @rtc. Errorcode %d. "
                    "Did you add write permission to the rtc cap?\n",
                    err);
  }

  // rtc server tells us that the time has changed
  // e.g. a suspend/resume cycle happened or a component set a new time
  void handle_irq()
  {
    if (_rtc->get_timer_offset(&_ns_offset))
      warn().printf("Could not read time @rtc.\n");
  }

  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "RTC"); }

private:
  // offset of kip_clock to epoch (wallclock time)
  l4_uint64_t _ns_offset;
  L4Re::Util::Unique_cap<L4::Irq> _irq;
};

}

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    L4::Cap<L4rtc::Rtc> cap = Vdev::get_cap<L4rtc::Rtc>(node, "l4vmm,rtccap");
    if (!cap)
      {
        Vdev::External_rtc::warn().printf("l4vmm,rtccap not valid. Will not have wallclock time.\n");
        return nullptr;
      }

    auto dev = Vdev::make_device<Vdev::External_rtc>(cap,
                                                     devs->vmm()->registry());

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"l4rtc", nullptr, &f};

} // namespace
