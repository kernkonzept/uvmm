/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
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

  virtual ~Acpi_platform()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("acpi_platform");
    a->add_compatible("virt-acpi");
    a->add_num_property("interrupts", 9);
    a->add_str_property("l4vmm,pwrinput", _res.as<std::string>("vcon_cap"));
  }
};

struct F: Device_factory<Acpi_platform>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    std::vector<Option> opts =
      {Option("vcon_cap", "vcon channel for acpi commands",
              make_parser<String_parser>(),
              make_default<std::string>("acpi_pwr_input")),};

    return Device_option("acpi-platform", "acpi platform device", this,
                         std::move(opts));
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "acpi-platform" };

}
