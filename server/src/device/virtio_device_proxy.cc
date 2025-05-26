/*
 * Copyright (C) 2017-2020, 2022-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "debug.h"
#include "device_factory.h"
#include "irq_dt.h"
#include "virtio_device_proxy.h"

namespace Vdev {

/**
 * Virtio proxy control device.
 *
 * Device for controlling dynamic addition/removal of Virtio proxy devices.
 * This needs a special l4 driver running within the guest OS.
 *
 * A device tree entry needs to look like this:
 *
 * \code{.dtb}
 *   virtio_proxy_ctl@7000 {
 *       compatible = "virtio-dev,mmio";
 *       // The first row holds the l4 config space for the controller device.
 *       // Must be 0x1000 bytes large.
 *       // The second row is reserved for the actual proxy devices. Every
 *       // device needs 0x2000. So multiply this with the amount of proxy
 *       // devices this controller should support. At the same time you need
 *       // to provide the same amount of irq's. In the following example, 2
 *       // virtio proxy devices are supported.
 *       reg = <0x0 0x7000 0x0 0x1000>,
 *             <0x0 0x8000 0x0 0x4000>;
 *       interrupts = <0 145 4>,
 *                    <0 146 4>;
 *       l4vmm,mempool = <&viodev_mp>;
 *   };
 * \endcode
 *
 * viodev_mp points to the node containing the memory pool for the foreign
 * guest memory. See the virtio mem pool documentation for details.
 */

class Virtio_device_proxy_control
: public Virtio_device_proxy_control_base
{
public:
  Virtio_device_proxy_control(l4_uint32_t max_devs,
                              Vmm::Guest *vmm,
                              cxx::Ref_ptr<Virtio_device_mem_pool> mempool,
                              l4_uint64_t l4cfg_addr, l4_uint64_t l4cfg_size,
                              std::vector<std::unique_ptr<Vmm::Irq_sink>> &&irq_sinks)
  : Virtio_device_proxy_control_base(max_devs, vmm, mempool),
    _irq_sinks(std::move(irq_sinks))
  {
    // Add devices l4/virtio config page region to vmm map
    vmm->add_mmio_device(Vmm::Region::ss(Vmm::Guest_addr(l4cfg_addr),
                                         l4cfg_size, Vmm::Region_type::Virtual),
                         cxx::Ref_ptr<Vmm::Mmio_device>(_prm));

    // Tell the start address to the region manager
    _prm->set_mapping_addr(Vmm::Guest_addr(l4cfg_addr));
  }

  void kick_irq(l4_uint32_t idx) override
  {
    _irq_sinks[idx]->inject();
  }

  void ack_irq(l4_uint32_t idx) override
  {
    _irq_sinks[idx]->ack();
  }

  std::vector<std::unique_ptr<Vmm::Irq_sink>> _irq_sinks;
};

} // namespace Vdev

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Vdev::Device_lookup *devs,
                              Dt_node const &node) override
  {
    Dbg info(Dbg::Dev, Dbg::Info, "proxy_ctl");
    Dbg warn(Dbg::Dev, Dbg::Warn, "proxy_ctl");

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

    l4_size_t l4cfg_count = l4cfg_size / (L4_PAGESIZE * 2);
    if (l4cfg_count < 1)
      {
        warn.printf("%s: reg entry for l4 config window is too small. At "
                    "least two pages are required for one virtio device "
                    "proxy.\n",
                    node.get_name());
        return nullptr;
      }

    std::vector<std::unique_ptr<Vmm::Irq_sink>> irq_sinks;
    Vdev::Irq_dt_iterator it(devs, node);
    while (!it.next(devs))
      {
        if (!it.ic_is_virt())
          {
            warn.printf("%s: virtio device proxy control requires a virtual "
                        "interrupt controller\n",
                        node.get_name());
            return nullptr;
          }

        irq_sinks.emplace_back(
          std::make_unique<Vmm::Irq_sink>(it.ic(), it.irq()));
      }

    if (irq_sinks.empty())
      {
        warn.printf("%s: no irq entries found. One irq is required "
                    "for one virtio device proxy.\n",
                    node.get_name());
        return nullptr;
      }


    l4_size_t max_devs = std::min(irq_sinks.size(), l4cfg_count);
    if (irq_sinks.size() != l4cfg_count)
      {
        warn.printf("%s: irq count and l4cfg window range differ. Using the "
                    "smaller count.\n",
                    node.get_name());
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

    auto c = make_device<Virtio_device_proxy_control>(max_devs,
                                                      devs->vmm(),
                                                      mempool,
                                                      l4cfg_addr, l4cfg_size,
                                                      std::move(irq_sinks));

    // register as mmio device for l4 config space
    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node, 0);

    info.printf("%s: virtio device proxy controller registered.\n",
                node.get_name());
    info.printf("%s:  max supported devs: %zu\n",
                node.get_name(), max_devs);

    return c;
  }
};

static F f;
static Device_type t = { "virtio-dev,mmio", nullptr, &f };

}
