/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Gic: Ic, Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section("gic", "gic");
    a->add_compatible({"arm,gic-400", "arm,cortex-a15-gic", "arm,cortex-a9-gic"});
    a->add_empty_property("interrupt-controller");
    a->add_address_cells(0);
    a->add_interrupt_cells(3);
    a->add_reg_property({Addr_type(_res.as<uint64_t>("addr_dist"),
                                   0x10000, dt->rm()),
                         Addr_type(_res.as<uint64_t>("addr_redist"),
                                   0x20000, dt->rm())});

    dt->root()->add_handle_property("interrupt-parent", "/l4vmm/gic");
  }

  std::string provides() const override
  { return "gic"; }

  std::vector<unsigned> next_irq() override
  { return { 0, _next_irq++, 4 }; }

private:
  unsigned _next_irq = 1;
};

struct F: Device_factory<Gic>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("gic", "gic interrupt controller", this,
             {Option("addr_dist", "fixed address of the device dist mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("addr_redist", "fixed address of the device redist mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>())});
  }

  int flags() const override
  { return Option::Default; }
};

static F f = { Arch::Arm | Arch::Mips, "gic" };

}
