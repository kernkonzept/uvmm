/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Virtio_console: Device
{
  using Device::Device;

  virtual ~Virtio_console()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section(name("virtio_console"));
    a->add_compatible("virtio,mmio");
    a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  0x1000, dt->rm()));
    a->add_str_property("l4vmm,vdev", "console");
    if (_res.has("vcon_cap"))
      a->add_str_property("l4vmm,vcon_cap", _res.as<std::string>("vcon_cap"));
  }
};

struct F: Device_factory<Virtio_console>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virtio-console", "virtio console device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("vcon_cap", "name of the vcon capability",
                     make_parser<String_parser>())});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> a_requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::Arm | Arch::Mips, "virtio-console" };

}
