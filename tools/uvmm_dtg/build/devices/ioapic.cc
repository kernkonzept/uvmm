/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Ioapic: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("ioapic", "ioapic");
    a->add_compatible("intel,ioapic");
    a->add_empty_property("interrupt-controller");
    a->add_interrupt_cells(1);
  }
};

struct F: Device_factory<Ioapic>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("ioapic", "ioapic interrupt controller", this); }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "ioapic" };

}
