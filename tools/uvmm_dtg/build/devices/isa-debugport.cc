/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Isa_debugport: Device
{
  using Device::Device;

  virtual ~Isa_debugport()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->section("/isa")->add_section("isa_debugport");
    a->add_compatible("l4vmm,isa-debugport");
    // Fixed IO-Port
    a->add_num_property("reg", {0x1, 0x402, 0x1});
    a->add_str_property("l4vmm,vcon_cap", _res.as<std::string>("vcon_cap"));
  }
};

struct F: Device_factory<Isa_debugport>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("isa-debugport", "simple debug channel device", this,
             {Option("vcon_cap", "name of the vcon capability",
                     make_parser<String_parser>(),
                     Option::Required)});
  }

  std::vector<std::string> a_requires() const override
  { return { "isa" }; }
};

static F f = { Arch::X86, "isa_debugport" };

}
