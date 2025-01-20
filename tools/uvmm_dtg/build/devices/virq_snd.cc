/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Virq_snd: Device
{
  using Device::Device;

  virtual ~Virq_snd()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section(name("virq_snd"));
    a->add_compatible("l4vmm,virq-snd");
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  0x4, dt->rm()));
    a->add_str_property("l4vmm,virqcap", _res.as<std::string>("virqcap"));
  }
};

struct F: Device_factory<Virq_snd>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virq-snd", "virtual irq send device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("virqcap", "name of the virq capability",
                     make_parser<String_parser>(),
                     Option::Required)});
  }

  int flags() const override
  { return Option::Multiple; }
};

static F f = { Arch::All, "virq-snd" };

}
