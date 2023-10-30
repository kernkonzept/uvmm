/*
 * Copyright (C) 2016-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cstdlib>

#include "mmio_device.h"
#include "debug.h"
#include "device.h"
#include "device_factory.h"
#include "guest.h"

namespace {

using namespace Vdev;

/**
 * A simple system controller with the following functions:
 *
 *   0x00 - On write exit with the given value as exit code.
 *
 * This device can be used with the generic syscon device from
 * Linux as follows:
 *
 *     vmm-syscon {
 *        #address-cells = <1>;
 *        #size-cells = <1>;
 *        compatible = "simple-bus";
 *        ranges = <0x0 0x30030000 0x4>;
 *
 *        l4syscon: syscon {
 *                compatible = "syscon", "syscon-l4vmm";
 *                reg = <0x0 0x4>;
 *                little-endian;
 *        };
 *
 *        reboot {
 *                compatible = "syscon-reboot";
 *                regmap = <&l4syscon>;
 *                offset = <0x0>;
 *                mask = <0x66>;
 *        };
 *
 *        poweroff {
 *                compatible = "syscon-poweroff";
 *                regmap = <&l4syscon>;
 *                offset = <0x0>;
 *                mask = <0x0>;
 *        };
 *    };
 *
 * The `l4syscon` entry defines this system controller device itself
 * and the additional entries the exact return code with which to exit
 * the uvmm.
 *
 * Note that reboot does not really reinitialise uvmm. This
 * still needs to be done by the application that started the uvmm (usually
 * ned). The exit code is simply used as a means to notify the starter that
 * a reboot was requested.
 */
struct System_controller : public Device
{
  System_controller(Vmm::Guest *vmm)
  : _vmm(vmm)
  {}

  l4_uint32_t read(unsigned, char, unsigned)
  { return 0; }

  void write(unsigned reg, char, l4_uint32_t value, unsigned)
  {
    switch (reg)
      {
      case 0:
        Dbg(Dbg::Dev, Dbg::Info, "sysctl")
          .printf("Shutdown (%d) requested\n", value);
        _vmm->shutdown(value);
      }
  }

private:
  Vmm::Guest *_vmm;
};

struct System_controller_mmio
: public System_controller,
  public Vmm::Mmio_device_t<System_controller_mmio>
{
  System_controller_mmio(Vmm::Guest *vmm)
  : System_controller(vmm)
  {}

  char const *dev_name() const override { return "System_controller_mmio"; }
};

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto syscon = make_device<System_controller_mmio>(devs->vmm());
    devs->vmm()->register_mmio_device(syscon, Vmm::Region_type::Virtual, node);
    return syscon;
  }
};

static F f;
static Vdev::Device_type t = { "syscon-l4vmm", nullptr, &f };

} // namespace
