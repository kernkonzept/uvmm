/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Kvm_clock: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("kvm_clock");
    a->add_compatible("kvm-clock");
  }
};

struct F: Device_factory<Kvm_clock>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("kvm-clock", "kvm clock device", this); }
};

static F f = { Arch::X86, "kvm-clock" };

}
