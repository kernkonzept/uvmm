/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"
#include "ic.h"

namespace {

struct Pci_host_ecam: Device
{
  using Device::Device;

  virtual ~Pci_host_ecam()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->root()->add_section("pcie", "",
                                     _trg_arch.acells + 1, _trg_arch.scells);
    a->add_compatible("pci-host-ecam-generic");
    a->add_device_type("pci");
    a->add_num_property("bus-range", {0, 0});
    a->add_num_property("#interrupt-cells", 1);

    a->add_num_property("interrupt-map-mask", {0x1800, 0x0, 0x0, 0x7});
    std::vector<std::vector<unsigned>> ints;
    // Create max 4 legacy irqs
    ints.insert(ints.end(), Ic::default_ic(_trg_arch)->next_irq());
    ints.insert(ints.end(), Ic::default_ic(_trg_arch)->next_irq());
    ints.insert(ints.end(), Ic::default_ic(_trg_arch)->next_irq());
    ints.insert(ints.end(), Ic::default_ic(_trg_arch)->next_irq());
    unsigned b = 0;
    std::vector<Mixed_type> map;
    std::string gic = "/l4vmm/gic";
    // Shuffle the 4 interrupts over the 4 device ids
    for (unsigned i = 0; i < 4; ++i)
      {
        map += {i << 11, 0x0, 0x0, 0x1, gic};
        map += ints[b];
        map += {i << 11, 0x0, 0x0, 0x2, gic};
        map += ints[(b + 1) % 4];
        map += {i << 11, 0x0, 0x0, 0x3, gic};
        map += ints[(b + 2) % 4];
        map += {i << 11, 0x0, 0x0, 0x4, gic};
        map += ints[(b + 3) % 4];
        b = (b + 1) % 4;
      }

    a->add_num_property("interrupt-map", std::move(map));
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                 0x1000000, dt->rm()));

    std::vector<Mixed_type> ranges;
    // io range (not managed by our region mapper)
    auto io1 = std::make_shared<Addr_type>(0x0, 0x0);
    auto io2 = std::make_shared<Addr_type>(0x3eff0000, 0x00010000);
    ranges += {0x1000000, Addr_ref(io1), Addr_ref(io2), Size_ref(io2)};

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

    a->add_num_property("ranges", std::move(ranges));
  }
};

struct F: Device_factory<Pci_host_ecam>
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

    return Device_option("pci-host-ecam", "pci host ecam bridge device", this,
                         std::move(opts));
  }

  std::vector<std::string> requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::Arm, "pci-host-ecam" };

}
