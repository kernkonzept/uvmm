/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Pic: Device
{
  using Device::Device;

  virtual ~Pic()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("pic", "PIC");
    a->add_compatible("virt-i8259-pic");
    a->add_empty_property("interrupt-controller");
    a->add_interrupt_cells(1);
    a->add_address_cells(0);
    a->add_handle_property("msi-parent", "/msictrl");
  }
};

struct F: Device_factory<Pic>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("pic", "pic interrupt controller", this); }

  std::vector<std::string> a_requires() const override
  { return { "msi-control" }; }

  int flags() const override
  { return Option::None; }
};

static F f = {Arch::X86, "pic" };

}
