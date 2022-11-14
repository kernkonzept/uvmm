/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Eisa: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("isa", "isa", 2, 1);
    a->add_device_type("eisa");

    std::vector<Mixed_type> ranges;
    auto mmio = std::make_shared<Addr_type>(_res.as<uint64_t>("addr"),
                                            0x1000000, dt->rm());
    // io range (not managed by our region mapper)
    auto io = std::make_shared<Addr_type>(0x0, 0x1000);
    ranges += {0, Addr_ref(mmio), Size_ref(mmio)};
    ranges += {1, Addr_ref(io), Size_ref(io)};

    a->add_position(mmio);
    a->add_num_property("ranges", std::move(ranges));
  }
};

struct F: Device_factory<Eisa>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("isa", "isa", this,
             {Option("addr", "fixed address of the device mmio region",
              make_parser<Addr_parser>(_trg_arch.is64bit),
              make_auto<Addr_default>())});
  }
};

static F f = { Arch::X86, "isa" };

}
