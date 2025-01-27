/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct L4Rtc: Device
{
  using Device::Device;

  virtual ~L4Rtc()
  {}

  void add(Tree *dt) override
  {
     auto b = dt->root()->add_section("l4rtc");
     b->add_compatible("l4rtc");
     b->add_str_property("l4vmm,rtccap", _res.as<std::string>("rtc_cap"));
  }
};

struct F: Device_factory<L4Rtc>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("l4rtc", "l4rtc device", this,
                         {Option("rtc_cap", "Capability for the l4rtc server",
                                 make_parser<String_parser>(),
                                 make_default<std::string>("rtc"))
                         });
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::All, "l4rtc" };

}
