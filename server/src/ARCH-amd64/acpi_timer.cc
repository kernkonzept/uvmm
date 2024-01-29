/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s):  Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 */

/**
 * The ACPI PM TIMER is documented in the ACPI Manual in Chapter 4.8.3.3
 * "Power Management Timer (PM_TMR)".
 *
 * Its IO port is 0xb008 by default.
 * "This is a 24-bit counter that runs off a 3.579545-MHz clock and counts
 *  while in the S0 working system state."
 *
 * The client has to cope with wrap arounds.
 *
 * This can be used in linux with cmdline "clocksource=acpi_pm".
 *
 * We do not support interrupt generation.
 */


#include "device_factory.h"
#include "guest.h"
#include "device.h"
#include "acpi.h"
#include "io_device.h"
#include <l4/re/env.h>
#include <l4/util/rdtsc.h>

namespace Vdev {

class Acpi_timer:
  public Vmm::Io_device,
  public Vdev::Device,
  public Acpi::Acpi_device
{
public:
  enum
    {
      Frequency_hz = 3579545,
      Port = 0xb008,
    };

  Acpi_timer()
  : Acpi_device()
  {
    _timebase = l4_rdtsc();
  }

  char const *dev_name() const override
  { return "ACPI Timer"; }

  void amend_fadt(ACPI_TABLE_FADT *t) const override
  {
    t->PmTimerBlock = Port;
    t->PmTimerLength = 4;
    t->Flags |= ACPI_FADT_32BIT_TIMER;
  }

private:
  /* IO write from the guest to device */
  void io_out(unsigned, Vmm::Mem_access::Width, l4_uint32_t) override
  {
    // this is a read only field, so we can ignore that.
    return;
  }

  /* IO read from the guest */
  void io_in(unsigned, Vmm::Mem_access::Width, l4_uint32_t *value) override
  {
    l4_cpu_time_t now = l4_rdtsc();
    l4_cpu_time_t diff_ns = l4_tsc_to_ns(now - _timebase);
    l4_cpu_time_t period = 1000UL * 1000 * 1000 / Frequency_hz;
    *value = diff_ns / period;
  }

  l4_cpu_time_t _timebase = 0;
};

} // namespace Vdev

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &) override
  {
    auto dev = Vdev::make_device<Vdev::Acpi_timer>();

    Acpi::info.printf("Acpi timer @ 0x%x\n", Vdev::Acpi_timer::Port);
    auto region = Vmm::Io_region(Vdev::Acpi_timer::Port,
                                 Vdev::Acpi_timer::Port,
                                 Vmm::Region_type::Virtual);
    devs->vmm()->add_io_device(region, dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"acpi-timer", nullptr, &f};

} // namespace
