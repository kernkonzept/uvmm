/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "pci_bridge.h"

namespace {

struct Virtio_proxy_pci: Device
{
  using Device::Device;

  virtual ~Virtio_proxy_pci()
  {}

  void add(Tree *dt) override
  {
    auto dev = Pci_bridge::next_dev_id();
    auto a = dt->section("/pci")->add_section(name("virtio_proxy_pci"));
    a->add_position(std::make_shared<Addr_type>(dev, 0));
    a->add_compatible("virtio,pci");
    a->add_num_property("reg",
                        {0x00000000 | dev << 11, 0x0, 0x0, 0x0, 0x0000,
                         0x02000010 | dev << 11, 0x0, 0x0, 0x0, 0x2000,
                         0x01000014 | dev << 11, 0x0, 0x0, 0x0,  0x100});
    a->add_str_property("l4vmm,vdev", "proxy");
    a->add_str_property("l4vmm,virtiocap", _res.as<std::string>("virtiocap"));
    if (_res.has("no-notify"))
      a->add_num_property("l4vmm,no-notify", _res.as<uint32_t>("no-notify"));
  }
};

struct F: Device_factory<Virtio_proxy_pci>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virtio-proxy-pci", "virtio proxy pci device", this,
             {Option("virtiocap", "name of the virtio capability",
                     make_parser<String_parser>(),
                     Option::Required),
              Option("no-notify", "queue number for no notify",
                     make_parser<UInt32_parser>())});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> a_requires() const override
  { return { "pci-bridge" }; }
};

static F f = { Arch::X86, "virtio-proxy-pci" };

}
