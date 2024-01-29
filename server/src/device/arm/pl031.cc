/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 */
/**
 * Simplistic emulation of an PL031 RTC. Does not come with complete device
 * model nor write support.
 *
 * Needs a device tree entry like this:
 *
 * rtc@11000 {
 *     compatible = "arm,pl031", "arm,primecell";
 *     reg = <0x0 0x00011000 0x0 0x1000>;
 *     clocks = <&apb_dummy_pclk>;
 *     clock-names = "apb_pclk";
 * };
 *
 * Linux also wants to have an entry for clocks like this:
 *
 * apb_dummy_pclk: dummy_clk {
 *     compatible = "fixed-clock";
 *     #clock-cells = <0>;
 *     clock-frequency = <1000000>;
 * };
 *
 */
#include "debug.h"
#include "device.h"
#include "device_factory.h"
#include "guest.h"
#include "mmio_device.h"

#include "../rtc-hub.h"

static Dbg warn(Dbg::Dev, Dbg::Warn, "pl031");
static Dbg info(Dbg::Dev, Dbg::Info, "pl031");

class Pl031
: public Vmm::Mmio_device_t<Pl031>,
  public Vdev::Device
{
  enum Registers
    {
      Dr = 0,       // Data Register
      Mr = 0x4,     // Match Register
      Lr = 0x8,     // Load Register
      Cr = 0xc,     // Control Register
      // Identification registers. Linux will parse these to detect the device.
      // RTCPeriphID0-3 peripheral identification registers
      pid0 = 0xfe0,
      pid1 = 0xfe4,
      pid2 = 0xfe8,
      pid3 = 0xfec,
      // RTCPCellID0-3 primecell identification registers
      cid0 = 0xff0,
      cid1 = 0xff4,
      cid2 = 0xff8,
      cid3 = 0xffc,
    };

public:
  l4_uint32_t read(unsigned reg, char /*size*/, unsigned /*cpu_id*/)
  {
    l4_uint32_t retval = 0;
    switch (reg)
      {
      case Dr:
        {
          l4_uint64_t t =
            Vdev::L4rtc_hub::ns_since_epoch();
          retval = t / 1000000000;
        }
        break;
      case Cr:
        retval = 1; // always on
        break;
      case pid0:
        retval = 0x31;
        break;
      case pid1:
        retval = 0x10;
        break;
      case pid2:
        retval = 0x14;
        break;
      case pid3:
        retval = 0;
        break;
      case cid0:
        retval = 0x0d;
        break;
      case cid1:
        retval = 0xf0;
        break;
      case cid2:
        retval = 0x5;
        break;
      case cid3:
        retval = 0xb1;
        break;
      default:
        warn.printf("Register read 0x%x not implemented\n", reg);
        break;
      }
    return retval;
  }

  void write(unsigned /*reg*/, char /*size*/, l4_uint32_t /*value*/, unsigned /*cpu_id*/)
  {
    warn.printf("RTC write access not implemented\n");
  }

  char const *dev_name() const override { return "Pl031"; }
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    info.printf("Register Pl031 device\n");

    auto c = Vdev::make_device<Pl031>();
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);

    return c;
  }
};

static F f;
static Vdev::Device_type t1 = { "arm,pl031", nullptr, &f };
