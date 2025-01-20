/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Ioapic: Ic, Device
{
  using Device::Device;

  virtual ~Ioapic()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("ioapic", "ioapic");
    a->add_compatible("intel,ioapic");
    a->add_empty_property("interrupt-controller");
    a->add_interrupt_cells(1);
    a->add_address_cells(0);
    a->add_handle_property("msi-parent", "/msictrl");

    dt->root()->add_handle_property("interrupt-parent", "/ioapic");
  }

  std::string provides() const override
  { return "ioapic"; }


  std::vector<unsigned> next_irq() override
  { return { _next_irq++ }; }

private:
  // starting at 10 seems to be safe
  // on x86 some Irqs are fixed: e.g.
  // 4 - ns8250
  // 8 - rtc
  // 9 - acpi
  unsigned _next_irq = 10;
};

struct F: Device_factory<Ioapic>
{
  using Device_factory::Device_factory;

  Option option() override
  { return Device_option("ioapic", "ioapic interrupt controller", this); }

  int flags() const override
  { return Option::None; }

  std::vector<std::string> requires() const override
  { return { "msi-control" }; }

};

static F f = { Arch::X86, "ioapic" };

}
