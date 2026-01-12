/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Psci: Device
{
  using Device::Device;

  virtual ~Psci()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("psci");
    a->add_compatible("arm,psci-1.0");
    a->add_str_property("method", _res.as<std::string>("method"));
  }
};

struct F: Device_factory<Psci>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("psci", "psci device", this,
             {Option("method", "method used for calling the hypervisor",
                     make_parser<Selector_parser, std::string>(
                       {{"hvc", "hvc"}, {"smc", "smc"}}),
                     make_default<std::string>("hvc"))});
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::Arm, "psci" };

}
