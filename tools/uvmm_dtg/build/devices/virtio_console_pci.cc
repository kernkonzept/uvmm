/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "pci_bridge.h"

namespace {

struct Virtio_console_pci: Device
{
  using Device::Device;

  void add(Tree *dt) override
  {
    auto dev = Pci_bridge::next_dev_id();
    auto a = dt->section("/pci")->add_section(name("virtio_console_pci"));
    a->add_position(std::make_shared<Addr_type>(dev, 0));
    a->add_compatible("virtio,pci");
    a->add_num_property("reg",
                        {0x00000000 | dev << 11, 0x0, 0x0, 0x0, 0x0000,
                         0x02000010 | dev << 11, 0x0, 0x0, 0x0, 0x2000,
                         0x01000014 | dev << 11, 0x0, 0x0, 0x0,   0x80});
    a->add_str_property("l4vmm,vdev", "console");
    if (_res.has("vcon_cap"))
      a->add_str_property("l4vmm,vcon_cap", _res.as<std::string>("vcon_cap"));
  }
};

struct F: Device_factory<Virtio_console_pci>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("virtio-console-pci", "virtio console pci device", this,
             {Option("vcon_cap", "name of the vcon capability",
                     make_parser<String_parser>())});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> requires() const override
  { return { "pci-bridge" }; }
};

static F f = { Arch::X86, "virtio-console-pci" };

}
