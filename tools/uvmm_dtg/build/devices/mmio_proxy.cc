/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Mmio_proxy: Device
{
  using Device::Device;

  virtual ~Mmio_proxy()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->l4vmm()->add_section(name("mmio_proxy"));
    a->add_compatible("l4vmm,l4-mmio");
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  _res.as<uint64_t>("size"), dt->rm()));
    a->add_str_property("l4vmm,mmio-cap", _res.as<std::string>("mmio-cap"));
    if (_res.has("mmio-offset"))
      a->add_num_property("l4vmm,mmio-offset", _res.as<uint64_t>("mmio-offset"));
    if (_res.has("dma-ranges"))
      a->add_empty_property("dma-ranges");
  }
};

struct F: Device_factory<Mmio_proxy>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("mmio-proxy", "mmio proxy device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("mmio-cap", "name of the dataspace/mmio space capability",
                     make_parser<String_parser>(),
                     Option::Required),
              Option("size", "size of the dataspace",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Ds_auto_value>("mmio-cap"),
                     Option::Required),
              Option("mmio-offset", "offset into the dataspace",
                     make_parser<Addr_parser>(_trg_arch.is64bit)),
              Option("dma-ranges", "add dma ranges",
                     make_parser<Switch_parser>())});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> a_requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::All, "mmio-proxy" };

}
