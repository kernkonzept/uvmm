/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Timer: Device
{
  using Device::Device;

  virtual ~Timer()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("timer");
    if (dt->is_arch(Arch::Arm32))
      a->add_compatible("arm,armv7-timer");
    else
      a->add_compatible("arm,armv8-timer");
    a->add_num_property("interrupts", { 1, 13, 0xf08, 1, 14, 0xf08, 1, 15, 0xf08, 1, 16, 0xf08 });
    a->add_empty_property("always-on");
  }
};

struct F: Device_factory<Timer>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("timer", "timer device", this); }

  int flags() const override
  { return Option::Default; }

  std::vector<std::string> a_requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::Arm, "arm_timer" };

}
