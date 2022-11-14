/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Memory: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto t = dt->root();
    auto a = t->add_section(name("memory"));
    a->add_device_type("memory");
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  _res.as<uint64_t>("size"),
                                  _res.as<uint32_t>("align"),
                                  dt->rm()));
    a->add_str_property("l4vmm,dscap", _res.as<std::string>("dscap"));
  }
};

struct F: Device_factory<Memory>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    uint32_t align = 12;
    if (_trg_arch.is(Arch::Arm64))
      align = 21;
    else if (_trg_arch.is(Arch::Arm32))
      align = 28;

    return Device_option("memory", "memory resource", this,
             {Option("addr", "fixed address of the ram region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("align", "alignment of auto address",
                     make_parser<UInt32_parser>(),
                     make_default<uint32_t>(align)),
              Option("size", "size of the ram region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Ds_auto_value>("dscap", "ram"),
                     Option::Required),
              Option("dscap", "name of the ram dataspace capability",
                     make_parser<String_parser>(),
                     make_default<std::string>("ram"))});
  }

  int flags() const override
  { return Option::Multiple; }
};

static F f = { Arch::All, "memory" };

}
