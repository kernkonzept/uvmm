/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Rtc: Device
{
  using Device::Device;

  virtual ~Rtc()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("rtc");
    a->add_compatible("virt-rtc");
    a->add_num_property("interrupts", 8);
  }
};

struct F: Device_factory<Rtc>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("rtc", "rtc device", this); }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "rtc" };

}
