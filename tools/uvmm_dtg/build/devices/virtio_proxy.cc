/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Virtio_proxy: Device
{
  using Device::Device;

  virtual ~Virtio_proxy()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section(name("virtio_proxy"));
    a->add_compatible("virtio,mmio");
    a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  0x1000, dt->rm()));
    a->add_str_property("l4vmm,vdev", "proxy");
    a->add_str_property("l4vmm,virtiocap", _res.as<std::string>("virtiocap"));
    if (_res.has("no-notify"))
      a->add_num_property("l4vmm,no-notify", _res.as<uint32_t>("no-notify"));
  }
};

struct F: Device_factory<Virtio_proxy>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virtio-proxy", "virtio proxy device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("virtiocap", "name of the virtio capability",
                     make_parser<String_parser>(),
                     Option::Required),
              Option("no-notify", "queue number for no notify",
                     make_parser<UInt32_parser>())});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> a_requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::Arm | Arch::Mips, "virtio-proxy" };

}
