/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Pit: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("pit");
    a->add_address_cells(0);
    a->add_compatible("virt-pit");
    a->add_num_property("interrupts", 0); // Fixed System timer irq
  }
};

struct F: Device_factory<Pit>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("pit", "pit timer", this); }

  std::vector<std::string> requires() const override
  { return { _trg_arch.ic }; }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "pit" };

}
