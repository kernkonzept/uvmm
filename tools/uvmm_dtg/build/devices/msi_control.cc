/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Msi_control: Device
{
  using Device::Device;

  virtual ~Msi_control()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("msictrl", "msictrl");
    a->add_compatible("intel,msi-controller");
    a->add_empty_property("msi-controller");
    a->add_num_property("#msi-cells", 0);
  }
};

struct F: Device_factory<Msi_control>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("msi-control", "msi controller", this); }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "msi-control" };

}
