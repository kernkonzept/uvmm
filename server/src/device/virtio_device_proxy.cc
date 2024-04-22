/*
 * Copyright (C) 2017-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "debug.h"
#include "device_factory.h"
#include "irq_dt.h"
#include "virtio_device_proxy.h"

namespace Vdev {

/**
 * Virtio proxy for a device exported from the VMM.
 *
 * Device for emulating a virtio device for the guest. Needs a special l4
 * driver running within the guest OS.
 *
 * A device tree entry needs to look like this:
 *
 * viodev@80000000 {
 *   compatible = "virtio-dev,mmio";
 *   // The first row holds the virtio config space. The second row is for the
 *   // l4 config space.
 *   reg = <0x0 0x82000000 0x0 0x1000>,
 *         <0x0 0x82001000 0x0 0x1000>;
 *   interrupts = <0 145 4>;
 *   l4vmm,virtiocap = "viodev0";
 *   l4vmm,mempool = <&viodev_mp>;
 * };
 *
 * viodev_mp points to the node containing the memory pool for the foreign
 * guest memory. See the virtio mem pool documentation for details.
 */

class Virtio_device_proxy : public Virtio_device_proxy_base
{
public:
  Virtio_device_proxy(cxx::Ref_ptr<Gic::Ic> const &ic, int irq,
                      L4::Cap<L4::Rcv_endpoint> ep, l4_size_t cfg_size,
                      l4_uint64_t l4cfg_addr, l4_uint64_t l4cfg_size,
                      Vmm::Guest *vmm,
                      cxx::Ref_ptr<Virtio_device_mem_pool> mempool)
  : Virtio_device_proxy_base(ep, cfg_size, l4cfg_size, vmm, mempool),
   _irq_sink(ic, irq)
  {
    l4virtio_set_feature(mmio_local_addr()->dev_features_map,
                         L4VIRTIO_FEATURE_VERSION_1);
    l4virtio_set_feature(mmio_local_addr()->dev_features_map,
                         L4VIRTIO_FEATURE_CMD_CONFIG);

    // Add l4 config page to vmm map
    vmm->add_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(l4cfg_addr),
                                         l4cfg_size, Vmm::Region_type::Virtual),
                         _l4cfg.ds_hdlr);
  }

  void irq_kick() override
  { _irq_sink.inject(); }

  void irq_ack() override
  { _irq_sink.ack(); }

private:
  Vmm::Irq_sink _irq_sink;
};

} // namespace Vdev

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Vdev::Device_lookup *devs,
                              Dt_node const &node) override
  {
    Dbg info(Dbg::Dev, Dbg::Info, "viodev");
    Dbg warn(Dbg::Dev, Dbg::Warn, "viodev");

    auto cap = Vdev::get_cap<L4::Rcv_endpoint>(node, "l4vmm,virtiocap");
    if (!cap)
      {
        warn.printf("%s: failed to read 'l4vmm,virtiocap'\n", node.get_name());
        return nullptr;
      }

    l4_uint64_t cfg_addr, cfg_size;
    if (node.get_reg_val(0, &cfg_addr, &cfg_size) < 0)
      {
        warn.printf("%s: reg entry for config window not found\n",
                    node.get_name());
        return nullptr;
      }

    l4_uint64_t l4cfg_addr, l4cfg_size;
    if (node.get_reg_val(1, &l4cfg_addr, &l4cfg_size) < 0)
      {
        warn.printf("%s: reg entry for l4 config window not found\n",
                    node.get_name());
        return nullptr;
      }

    Vdev::Irq_dt_iterator it(devs, node);
    if (it.next(devs) < 0)
      {
        warn.printf("%s: virtio device proxy requires interrupt setup\n",
                    node.get_name());
        return nullptr;
      }

    if (!it.ic_is_virt())
      {
        warn.printf("%s: virtio device proxy requires a virtual interrupt controller\n",
                    node.get_name());
        return nullptr;
      }

    cxx::Ref_ptr<Virtio_device_mem_pool> mempool;
    int size = 0;
    auto *prop = node.get_prop<fdt32_t>("l4vmm,mempool", &size);
    if (prop && size > 0)
      {
        auto mp_node = node.find_phandle(*prop);
        if (mp_node.is_valid())
          mempool =
            cxx::dynamic_pointer_cast<Virtio_device_mem_pool>(
              devs->device_from_node(mp_node));
      }

    if (!mempool)
      {
        warn.printf("%s: virtio device memory pool device not found\n",
                    node.get_name());
        return nullptr;
      }

    auto c = make_device<Virtio_device_proxy>(it.ic(),
                                              it.irq(),
                                              cap, cfg_size,
                                              l4cfg_addr, l4cfg_size,
                                              devs->vmm(),
                                              mempool);

    // register as mmio device for config space
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node, 0);

    info.printf("%s: virtio device proxy registered\n", node.get_name());
    return c;
  }
};

static F f;
static Device_type t = { "virtio-dev,mmio", nullptr, &f };

}
