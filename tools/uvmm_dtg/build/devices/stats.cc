/*
 * Copyright (C) 2023 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld steffen.liebergeld@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Stats: Device
{
  using Device::Device;

  virtual ~Stats()
  {}

  void add(Tree *dt) override
  {
    if (_res.has("statscap"))
      {
        auto b = dt->root()->add_section("stats");
        b->add_compatible("l4vmm,stats");
        b->add_str_property("l4vmm,statscap", _res.as<std::string>("statscap"));
      }
  }
};

struct F: Device_factory<Stats>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("stats", "statistics interface", this,
                         {Option("statscap",
                                 "Capability for the statistics interface",
                                 make_parser<String_parser>())
                         });
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "stats" };

}
