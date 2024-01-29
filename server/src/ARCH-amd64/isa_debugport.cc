/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s):  Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */

/**
 * This implements a simple debug channel, similar to the ones implemented in
 * Qemu and Bochs.
 *
 * This can be used for low-level debugging of guests.
 *
 * Example DT:
 *
 *      isa {
 *          device_type = "eisa";
 *          #address-cells = <2>;
 *          #size-cells = <1>;
 *          // The first cell of a child nodes reg property encodes the
 *          // following information. See the ISA bus device-tree binding [2]
 *          // for more details:
 *          //
 *          //  [2] 11-bit aliased (IOPORT only)
 *          //  [1] 10-bit aliased (IOPORT only)
 *          //  [0] 0=MMIO32, 1=IOPORT
 *          //
 *          // The standard ranges property defines the translation of child
 *          // reg address entries into the parent address space. Effectively
 *          // removes the upper word. For the purpose of the ISA translation,
 *          // only bit [0] is considered of the first word.
 *          ranges = <0x0 0x0 0x0 0x0 0xffffffff
 *                    0x1 0x0 0x0 0x0     0x1000>;

 *          isa_debugport {
 *              compatible = "l4vmm,isa-debugport";
 *              reg = <0x1 0x402 0x1>;
 *              l4vmm,vcon_cap = "debug";
 *          };
 *      };
 s
 */

#include "device_factory.h"
#include "guest.h"
#include "device.h"
#include "io_device.h"

namespace Vdev {

class Isa_debugport : public Vmm::Io_device, public Vdev::Device
{
  enum { Bochs_debug_port_magic = 0xe9 };

public:
  explicit Isa_debugport(L4::Cap<L4::Vcon> con)
  : _con(con)
  {
    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        Dbg(Dbg::Dev, Dbg::Warn, "cons")
          .printf("WARNING: Cannot set console attributes. "
                  "Output may not work as expected.\n");
        return;
      }

    attr.set_raw();
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
  }

  char const *dev_name() const override
  { return "ISA Debugport"; }

private:
  /* IO write from the guest to device */
  void io_out(unsigned, Vmm::Mem_access::Width, l4_uint32_t value) override
  {
    char s = value & 0xff;
    _con->write(&s, 1);
  }

  /* IO read from the guest */
  void io_in(unsigned, Vmm::Mem_access::Width, l4_uint32_t *value) override
  {
    *value = Bochs_debug_port_magic;
  }

  L4::Cap<L4::Vcon> _con;
};

} // namespace Vdev

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    L4::Cap<L4::Vcon> cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,vcon_cap");

    // Do not default to anything. If the cap is not there, there is no
    // debugport.
    if (!cap)
      return nullptr;

    auto dev = Vdev::make_device<Vdev::Isa_debugport>(cap);
    devs->vmm()->register_io_device(dev, Vmm::Region_type::Virtual, node);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"l4vmm,isa-debugport", nullptr, &f};

} // namespace
