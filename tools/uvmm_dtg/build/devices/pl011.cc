/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Pl011: Device
{
  using Device::Device;

  virtual ~Pl011()
  {}

  void add(Tree *dt) override
  {
    auto n = name("pl011");
    auto a = dt->l4vmm()->add_section(n, n);
    a->add_compatible({"arm,primecell", "arm,pl011"});
    a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"), 0x1000, dt->rm()));
    a->add_str_property("clock-names", "apb_pclk");
    a->add_handle_property("clocks", "/sysclk");
    if (_res.has("vcon_cap"))
      a->add_str_property("l4vmm,vcon_cap", _res.as<std::string>("vcon_cap"));

    auto b = dt->section("/chosen");
    b->add_str_property("stdout-path", a->path());
  }
};

struct F: Device_factory<Pl011>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("pl011", "pl011 uart device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("vcon_cap", "name of the vcon capability",
                     make_parser<String_parser>())});
  }

  int flags() const override
  { return Option::Default; }

  std::vector<std::string> a_requires() const override
  {
    if (_trg_arch.is(Arch::X86))
      return { _trg_arch.ic };
    return { _trg_arch.ic, "sysclock" };
  }
};

static F f = { Arch::Arm | Arch::Mips, "pl011" };

}
