/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Ns8250: Device
{
  using Device::Device;

  virtual ~Ns8250()
  {}

  void add(Tree *dt) override
  {
    auto t = _trg_arch.is(Arch::X86) ? dt->root() : dt->l4vmm();
    auto a = t->add_section("ns8250");
    a->add_compatible({"ns8250", "uart,8250" });
    if (!_trg_arch.is(Arch::X86))
      {
        a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                      0x1000, dt->rm()));
        a->add_str_property("clock-names", "apb_pclk");
        a->add_handle_property("clocks", "/sysclk");
        a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
      }
    else
      a->add_num_property("interrupts", _res.as<uint8_t>("irqnum"));

    if (_res.has("vcon_cap"))
      a->add_str_property("l4vmm,vcon_cap", _res.as<std::string>("vcon_cap"));
  }
};

struct F: Device_factory<Ns8250>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    std::vector<Option> opts;
    if (!_trg_arch.is(Arch::X86))
      opts.emplace_back("addr", "fixed address of the device mmio region",
                        make_parser<Addr_parser>(_trg_arch.is64bit),
                        make_auto<Addr_default>());
    else
      opts.emplace_back("irqnum", "fixed irq number (on x86: com1 = 4, com2 = 3)",
                       make_parser<UInt8_parser>(),
                       Option::Required);

    opts.emplace_back("vcon_cap", "name of the vcon capability",
                      make_parser<String_parser>());

    return Device_option("ns8250", "8250 uart device", this,
                         std::move(opts));
  }

  int flags() const override
  {
    if (_trg_arch.is(Arch::X86))
      return Option::Default;
    return Option::None;
  }

  std::vector<std::string> requires() const override
  {
    if (_trg_arch.is(Arch::X86))
      return { _trg_arch.ic };
    return { _trg_arch.ic, "sysclock" };
  }
};

static F f = { Arch::All, "ns8250" };

}
