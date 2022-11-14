/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Optee: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("firmware")->add_section("optee");
    a->add_compatible("linaro,optee-tz");
    a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
    a->add_str_property("l4vmm,cap", _res.as<std::string>("cap"));
    a->add_str_property("method", _res.as<std::string>("method"));
    if (_res.has("dscap"))
      a->add_str_property("l4vmm,dscap", _res.as<std::string>("dscap"));
  }
};

struct F: Device_factory<Optee>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("optee", "optee device", this,
             {Option("cap", "name of the smccc capability",
                     make_parser<String_parser>(),
                     make_default<std::string>("smccc")),
              Option("dscap", "name of the optional dataspace capability",
                     make_parser<String_parser>()),
              Option("method", "method used for calling the optee",
                     make_parser<Selector_parser, std::string>(
                       {{"hvc", "hvc"}, {"smc", "smc"}}),
                     make_default<std::string>("smc"))});
  }

  std::vector<std::string> requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::Arm, "optee" };

}
