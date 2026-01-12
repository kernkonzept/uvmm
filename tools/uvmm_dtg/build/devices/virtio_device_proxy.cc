/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Virtio_device_proxy: Device
{
  using Device::Device;

  virtual ~Virtio_device_proxy()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section(name("virtio_device_proxy"));
    a->add_compatible("virtio-dev,mmio");
    a->add_num_property("interrupts", Ic::default_ic(_trg_arch)->next_irq());
    // If this is a 64bit arch, start searching for the client memory region
    // above 4GB
    auto min = _trg_arch.is64bit ? std::numeric_limits<uint32_t>::max() :
                               std::numeric_limits<uint32_t>::min();
    a->add_reg_property({Addr_type(_res.as<uint64_t>("addr"),
                                   0x1000, dt->rm()),
                         Addr_type(_res.as<uint64_t>("addr-client"),
                                   _res.as<uint64_t>("size-client"), dt->rm(),
                                   min)});
    a->add_str_property("l4vmm,virtiocap", _res.as<std::string>("virtiocap"));
  }
};

struct F: Device_factory<Virtio_device_proxy>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virtio-device-proxy", "virtio device proxy device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("virtiocap", "name of the virtio capability",
                     make_parser<String_parser>(),
                     Option::Required),
              Option("addr-client", "fixed address of the client memory region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("size-client", "the size of the client memory region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     Option::Required)});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> a_requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::Arm | Arch::Mips, "virtio-device-proxy" };

}
