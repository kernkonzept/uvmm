/*
 * Copyright (C) 2022, 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

namespace {

struct Qemu_fw_if: Device
{
  using Device::Device;

  virtual ~Qemu_fw_if()
  {}

  void add(Tree *dt) override
  {
    auto a = dt->section("/isa")->add_section("qemu_fw_if");
    a->add_compatible("l4vmm,qemu-fw-cfg");
    // Fixed IO-Port
    a->add_num_property("reg", {0x1, 0x510, 0xc});
    if (_res.has("kernel"))
      a->add_str_property("l4vmm,kernel", _res.as<std::string>("kernel"));
    else
      a->add_str_property("l4vmm,kernel", "");
    if (_res.has("ramdisk"))
      a->add_str_property("l4vmm,ramdisk", _res.as<std::string>("ramdisk"));
    else
      a->add_str_property("l4vmm,ramdisk", "");
    if (_res.has("cmdline"))
      a->add_str_property("l4vmm,cmdline", _res.as<std::string>("cmdline"));
    else
      a->add_str_property("l4vmm,cmdline", "");
  }
};

struct F: Device_factory<Qemu_fw_if>
{
  using Device_factory::Device_factory;

  Option option() override
  {
    return Device_option("qemu-fw-if", "qemu firmware interface device", this,
             {Option("kernel", "name of the kernel image",
                     make_parser<String_parser>()),
              Option("ramdisk", "name of the ramdisk image",
                     make_parser<String_parser>()),
              Option("cmdline", "command line to provide",
                     make_parser<String_parser>())});
  }

  std::vector<std::string> a_requires() const override
  { return { "isa" }; }
};

static F f = { Arch::X86, "qemu_fw_if" };

}
