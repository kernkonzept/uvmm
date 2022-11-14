/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Acpi_timer: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("acpi-timer");
    a->add_compatible("acpi-timer");
  }
};

struct F: Device_factory<Acpi_timer>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("acpi-timer", "acpi timer device", this); }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "acpi-timer" };

}
