/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "pci_bridge.h"

void Pci_bridge::add(Tree *dt)
{
  auto a = dt->root()->add_section("pci", "pci", 3, 2);
  a->add_compatible("virt-pci-bridge");
  a->add_device_type("pci");
  a->add_handle_property("interrupt-parent", "/ioapic");
  a->add_handle_property("msi-parent", "/msictrl");
  a->add_num_property("bus-range", {0, 0xff});
  a->add_num_property("#interrupt-cells", 1);

  // ECAM MCFG window
  a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                0x10000000, dt->rm()));

  std::vector<Mixed_type> ranges;
  // io range (not managed by our region mapper)
  auto io =
    std::make_shared<Addr_type>(0x6000, 0xa000);

  ranges += {0x1000000, Addr_ref(io), Addr_ref(io), Size_ref(io)};

  // mmio32 range
  auto mmio32 =
    std::make_shared<Addr_type>(_res.as<uint32_t>("mmio32-size"),
                                dt->rm(),
                                std::numeric_limits<uint32_t>::min(),
                                std::numeric_limits<uint32_t>::max());
  ranges += {0x2000000, Addr_ref(mmio32), Addr_ref(mmio32), Size_ref(mmio32)};

  if (_trg_arch.is64bit)
    {
      // mmio64 range
      auto mmio64 =
        std::make_shared<Addr_type>(_res.as<uint64_t>("mmio64-size"),
                                    dt->rm(),
                                    std::numeric_limits<uint32_t>::max());
      ranges += {0x3000000, Addr_ref(mmio64), Addr_ref(mmio64), Size_ref(mmio64)};
    }

  a->add_position(mmio32);
  a->add_num_property("ranges", std::move(ranges));
}

unsigned Pci_bridge::_dev_ids = 0;

namespace {

struct F: Device_factory<Pci_bridge>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    std::vector<Option> opts =
      {Option("addr", "fixed address of the device mmio region",
              make_parser<Addr_parser>(_trg_arch.is64bit),
              make_auto<Addr_default>()),
       Option("mmio32-size", "size of the 32bit pci window",
              make_parser<UInt32_parser>(),
              make_default<uint32_t>(0x1000000))};

    if (_trg_arch.is64bit)
      opts.emplace_back("mmio64-size", "size of the 64bit pci window",
                        make_parser<UInt64_parser>(),
                        make_default<uint64_t>(0x1000000));

    return Device_option("pci-bridge", "pci bridge device", this,
                        std::move(opts));
  }

  std::vector<std::string> a_requires() const override
  { return { "ioapic", "msi-control" }; }
};

static F f = { Arch::X86, "pci-bridge" };

}
