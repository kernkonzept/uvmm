/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Framebuffer: Device
{
  using Device::Device;

  virtual ~Framebuffer()
  {}

  /*      simplefb {
   *            compatible = "simple-framebuffer";
   *            reg = <0x0 0xf0000000 0x0 0x1000000>;
   *            l4vmm,fbcap = "fb";
   *            l4vmm,refresh_rate = 30;
   *      };
   */
  void add(Tree *dt) override
  {
    auto a = dt->add_section("framebuffer");
    a->add_compatible("simple-framebuffer");
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  _res.as<uint64_t>("size"),
                                  _res.as<uint32_t>("align"),
                                  dt->rm()));
    a->add_str_property("l4vmm,fbcap", _res.as<std::string>("fbcap"));
    a->add_num_property("l4vmm,refresh_rate", _res.as<uint32_t>("refresh_rate"));
  }
};

struct F: Device_factory<Framebuffer>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    uint32_t align = 12;
    if (_trg_arch.is(Arch::Arm64))
      align = 21;
    else if (_trg_arch.is(Arch::Arm32))
      align = 28;

    return Device_option("framebuffer", "simple framebuffer", this,
             {Option("addr", "fixed address of the framebuffer memory region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_default<uint64_t>(0xf0000000)),
              Option("align", "alignment of auto address",
                     make_parser<UInt32_parser>(),
                     make_default<uint32_t>(align)),
              Option("size", "size of the framebuffer memory region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_default<uint64_t>(0x1000000)),
              Option("fbcap", "name of the framebuffer capability",
                     make_parser<String_parser>(),
                     make_default<std::string>("fb")),
              Option("refresh_rate", "rate of the full refresh",
                     make_parser<UInt32_parser>(),
                     make_default<uint32_t>(30))});
  }
};

static F f = { Arch::All, "framebuffer" };

}
