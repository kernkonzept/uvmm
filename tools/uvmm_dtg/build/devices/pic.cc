/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Pic: Ic, Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("pic", "pic");
    a->add_compatible("virt-i8259-pic");
    a->add_empty_property("interrupt-controller");
    a->add_interrupt_cells(1);
    a->add_handle_property("msi-parent", "/msictrl");

    dt->root()->add_handle_property("interrupt-parent", "/pic");
  }

  std::string provides() const override
  { return "pic"; }


  std::vector<unsigned> next_irq() override
  { return { _next_irq++ }; }

private:
  unsigned _next_irq = 3; // starting at 3 seems to be safe
};

struct F: Device_factory<Pic>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("pic", "pic interrupt controller", this); }

  std::vector<std::string> requires() const override
  { return { "msi-control" }; }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::X86, "pic" };

}
