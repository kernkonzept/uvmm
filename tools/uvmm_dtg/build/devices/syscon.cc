/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Syscon: Device
{
  using Device::Device;

  virtual ~Syscon()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section("vmm-syscon");
    a->add_default_cells();
    a->add_compatible("simple-bus");
    a->add_empty_property("ranges");

    auto b = a->add_section("syscon", "l4syscon");
    b->add_compatible({"syscon", "syscon-l4vmm"});
    b->add_reg_property(Addr_type(_res.as<uint64_t>("addr"), 0x4, dt->rm()));
    b->add_empty_property("little-endian");

    b = a->add_section("reboot");
    b->add_compatible("syscon-reboot");
    b->add_handle_property("regmap", "/l4vmm/vmm-syscon/syscon");
    b->add_num_property("offset", 0);
    b->add_num_property("mask", _res.as<uint32_t>("reboot-mask"));

    b = a->add_section("poweroff");
    b->add_compatible("syscon-poweroff");
    b->add_handle_property("regmap", "/l4vmm/vmm-syscon/syscon");
    b->add_num_property("offset", 0);
    b->add_num_property("mask", _res.as<uint32_t>("poweroff-mask"));
  }
};

struct F: Device_factory<Syscon>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("syscon", "system controller device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("reboot-mask", "return value on reboot",
                     make_parser<UInt32_parser>(),
                     make_default<uint32_t>(0x66)),
              Option("poweroff-mask", "return value on poweroff",
                     make_parser<UInt32_parser>(),
                     make_default<uint32_t>(0))});
  }
};

static F f = { Arch::Arm | Arch::Mips, "syscon" };

}
