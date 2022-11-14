/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Cpu: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("cpus", "", 1, 0);
    for (size_t n = 0; n < _res.as<uint32_t>("num"); ++n)
      {
        auto b = a->add_section("cpu@" + std::to_string(n),
                                "cpu" + std::to_string(n));
        b->add_device_type("cpu");
        b->add_num_property("reg", n);
        if (_trg_arch.is(Arch::Arm32))
          {
            b->add_compatible("arm,armv7");
            b->add_str_property("enable-method", "psci");
          }
        else if (_trg_arch.is(Arch::Arm64))
          {
            b->add_compatible("arm,armv8");
            b->add_str_property("enable-method", "psci");
          }
        else if (_trg_arch.is(Arch::X86))
          b->add_compatible("virt-intel");
        else if (_trg_arch.is(Arch::Mips32))
          b->add_compatible("mips,p5600");
        else if (_trg_arch.is(Arch::Mips64))
          b->add_compatible("mips,i6400");
      }
  }
};

struct F : Device_factory<Cpu>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("cpu", "cpu resource", this,
             {Option("num", "amount of cpu cores",
                     make_parser<UInt32_parser>(1),
                     std::make_shared<Cpu_auto_value>())});
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::All, "cpu" };

}
