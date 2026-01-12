/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Sysclock: Device
{
  using Device::Device;

  virtual ~Sysclock()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("sysclk", "sysclk");
    a->add_compatible("fixed-clock");
    a->add_num_property("#clock-cells", 0);
    a->add_num_property("clock-frequency", 1000000);
  }
};

struct F: Device_factory<Sysclock>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("sysclock", "fixed clock device", this); }
};

static F f = { Arch::All, "sysclock" };

}
