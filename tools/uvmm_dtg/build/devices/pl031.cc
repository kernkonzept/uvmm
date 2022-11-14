/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Pl031: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section("pl031");
    a->add_compatible({"arm,primecell", "arm,pl031"});
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"), 0x1000, dt->rm()));
    a->add_str_property("clock-names", "apb_pclk");
    a->add_handle_property("clocks", "/sysclk");
  }
};

struct F: Device_factory<Pl031>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("pl031", "pl031 rtc device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>())});
  }

  std::vector<std::string> requires() const override
  { return { "sysclock" }; }
};

static F f = { Arch::Arm, "pl031" };

}
