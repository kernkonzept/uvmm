/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Virq_rcv: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section(name("virq_rcv"));
    a->add_compatible("l4vmm,virq-rcv");
    a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
    a->add_str_property("l4vmm,virqcap", _res.as<std::string>("virqcap"));
  }
};

struct F: Device_factory<Virq_rcv>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virq-rcv", "virtual irq receive device", this,
             {Option("virqcap", "name of the virq capability",
                     make_parser<String_parser>(),
                     Option::Required)});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::All, "virq-rcv" };

}
