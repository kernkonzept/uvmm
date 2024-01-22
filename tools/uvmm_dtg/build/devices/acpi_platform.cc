/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Acpi_platform: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("acpi_platform");
    a->add_compatible("virt-acpi");
    a->add_num_property("interrupts", 9);
  }
};

struct F: Device_factory<Acpi_platform>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("acpi-platform", "acpi platform device", this); }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "acpi-platform" };

}
