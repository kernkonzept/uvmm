/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Rom: Device
{
  using Device::Device;

  virtual ~Rom()
  {}

  void add(Tree *dt) override
  {
    auto t = _trg_arch.is(Arch::X86) ? dt->root() : dt->l4vmm();
    auto a = t->add_section("rom");
    a->add_compatible("l4vmm,rom");
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  _res.as<uint64_t>("size"), dt->rm()));
    a->add_str_property("l4vmm,dscap", _res.as<std::string>("dscap"));
  }
};

struct F: Device_factory<Rom>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("rom", "read only memory", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("dscap", "name of the dataspace capability",
                     make_parser<String_parser>(),
                     Option::Required),
              Option("size", "size of the dataspace",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Ds_auto_value>("dscap"),
                     Option::Required)});
  }
};

static F f = { Arch::All, "rom" };

}
