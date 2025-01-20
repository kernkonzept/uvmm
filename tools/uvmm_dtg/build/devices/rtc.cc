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

    if (_res.has("rtc_cap"))
      {
        auto b = dt->root()->add_section("l4rtc");
        b->add_compatible("l4rtc");
        b->add_str_property("l4vmm,rtccap", _res.as<std::string>("rtc_cap"));
      }
  }
};

struct F: Device_factory<Rtc>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("rtc", "rtc device", this,
                         {Option("rtc_cap", "Capability for the l4rtc server",
                                 make_parser<String_parser>())
                         });
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "rtc" };

}
