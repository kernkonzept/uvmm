/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Cfi: Device
{
  using Device::Device;

  virtual ~Cfi()
  {}

  void add(Tree *dt) override
  {
    if (!_res.has("dscap") && !_res.has("virtiocap"))
      {
        printf("Error, device cfi requires either dscap or virtiocap\n");
        return;
      }
    if (_res.has("dscap") && _res.has("virtiocap"))
      {
        printf("Error, device cfi cannot cope with both dscap and virtiocap. Choose one.\n");
        return;
      }
    auto a = dt->l4vmm()->add_section(name("cfi"));
    a->add_compatible("cfi-flash");
    a->add_reg_property(Addr_type(_res.as<uint64_t>("addr"),
                                  _res.as<uint64_t>("size"), dt->rm()));
    if (_res.has("dscap"))
      a->add_str_property("l4vmm,dscap", _res.as<std::string>("dscap"));
    if (_res.has("virtiocap"))
      a->add_str_property("l4vmm,virtiocap", _res.as<std::string>("virtiocap"));
    if (_res.has("erase-size"))
      a->add_num_property("erase-size", _res.as<uint64_t>("erase-size"));
    if (_res.has("bank-width"))
      a->add_num_property("bank-width", _res.as<uint64_t>("bank-width"));
    if (_res.has("device-width"))
      a->add_num_property("device-width", _res.as<uint64_t>("device-width"));
    if (_res.has("read-only"))
      a->add_empty_property("read-only");
  }
};

struct F: Device_factory<Cfi>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("cfi", "common flash memory interface device", this,
             {Option("addr", "fixed address of the device mmio region",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     make_auto<Addr_default>()),
              Option("dscap", "name of the dataspace capability",
                     make_parser<String_parser>()),
              Option("virtiocap", "name of the virtio capability",
                     make_parser<String_parser>()),
              Option("size", "size of the dataspace",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     Option::Required),
              Option("erase-size", "erase block size (must be power of two)",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     Option::Required),
              Option("bank-width", "bank width of the device",
                     make_parser<Addr_parser>(_trg_arch.is64bit),
                     Option::Required),
              Option("device-width", "width of the device",
                     make_parser<Addr_parser>(_trg_arch.is64bit)),
              Option("read-only", "map device read only",
                     make_parser<Switch_parser>())});
  }

  int flags() const override
  { return Option::Multiple; }

  std::vector<std::string> requires() const override
  { return { _trg_arch.ic }; }
};

static F f = { Arch::All, "cfi" };

}
