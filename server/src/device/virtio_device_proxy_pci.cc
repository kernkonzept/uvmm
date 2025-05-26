/*
 * Copyright (C) 2023-2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "debug.h"
#include "device_factory.h"
#include "pci_device.h"
#include "pci_host_bridge.h"
#include "virtio_pci_connector.h"
#include "event_connector_pci.h"

#include "virtio_device_proxy.h"

namespace Vdev {

using namespace Pci;

/**
 * PCI Virtio proxy control device.
 *
 * Device for controlling dynamic addition/removal of Virtio proxy devices.
 * This needs a special L4 driver running within the guest OS.
 *
 * A device tree entry needs to look like this:
 *
 * \code{.dtb}
 *   pci0: pci@aa000000 {
 *       compatible = "virt-pci-bridge";
 *       ...
 *       ranges = <0x01000000 0x0 0x00006000 0x0 0x00006000 0x0     0xa000
 *                 0x02000000 0x0 0x8a000000 0x0 0x8a000000 0x0 0x20000000
 *                 0x03000000 0x2 0x00000000 0x2 0x00000000 0x1 0x00000000>;
 *       ...
 *       virtio_proxy_ctl@3 {
 *           compatible = "virtio,pci";
 *           msi-parent = <&msi_ctrl>;
 *           l4vmm,vdev = "device-proxy-controller";
 *           l4vmm,mempool = <&viodev_mp>;
 *       };
 *       ...
 *   };
 * \endcode
 *
 * viodev_mp points to the node containing the memory pool for the foreign
 * guest memory. See the virtio mem pool documentation for details.
 */
class Virtio_device_proxy_control_pci
: public Virtio_device_proxy_control_base,
  public Pci::Virt_pci_device
{
  // PCI device id is L4Re specific
  static constexpr unsigned Virtio_pci_device_id_proxy = 51;

public:
  Virtio_device_proxy_control_pci(l4_uint32_t max_devs,
                                  Vmm::Guest *vmm,
                                  cxx::Ref_ptr<Virtio_device_mem_pool> mempool,
                                  Gic::Msix_dest const &msix_dest,
                                  Pci_host_bridge *pci)
  : Virtio_device_proxy_control_base(max_devs, vmm, mempool),
    _evcon(max_devs, msix_dest)
  {
    // msix
    l4_addr_t addr =
      pci->bridge_windows()->alloc_bar_resource(_evcon.mem_size(),
                                                Pci_cfg_bar::Type::MMIO32);
    set_mem_space<Pci_header::Type0>(0, addr, _evcon.mem_size());
    // Add the bar containing the control mmio region which we use to
    // communicate with the guest
    addr =
      pci->bridge_windows()->alloc_bar_resource(L4_PAGESIZE,
                                                Pci_cfg_bar::Type::MMIO32);
    set_mem_space<Pci_header::Type0>(1, addr, L4_PAGESIZE);

    addr =
      pci->bridge_windows()->alloc_bar_resource(
        Proxy_region_mapper::max_mem_size(max_devs), Pci_cfg_bar::Type::MMIO32);
    set_mem_space<Pci_header::Type0>(2, addr,
      Proxy_region_mapper::max_mem_size(max_devs));
    _prm->set_mapping_addr(Vmm::Guest_addr(addr));

    Pci_msix_cap *cap    = create_pci_cap<Pci_msix_cap>();
    cap->ctrl.enabled()  = 1;
    cap->ctrl.masked()   = 0;
    cap->ctrl.max_msis() = max_devs - 1;
    cap->tbl.bir()       = 0;
    cap->pba.offset()    = Vdev::Msix::msix_table_mem_size(max_devs) >> 3;
    cap->pba.bir()       = 0;

    auto *const hdr = get_header<Pci_header::Type0>();
    hdr->vendor_id = Virtio_pci_device_vendor_id;
    // PCI device_id is calculated by Virtio Device ID + 0x1040
    // (see virtio 1.0 cs4)
    hdr->device_id = Virtio_pci_device_id_base + Virtio_pci_device_id_proxy;
    hdr->revision_id = Non_transitional_device_pci_revision_id;
    hdr->subsystem_id = Virtio_pci_subsystem_id_minimum;
    // hdr->subsystem_id && hdr->subsystem_vendor: virtio spec 1.0 cs4: optional
    hdr->status = Interrupt_status_bit | Capability_list_bit;
    hdr->header_type = Multi_func_bit;
    hdr->classcode[2] = Pci_class_code_other_device;
  }

  void kick_irq(l4_uint32_t idx) override
  {
    _evcon.send_event(idx);
  }

private:
  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned i) override
  {
    if (i == 0)
      return event_connector()->make_mmio_device();
    else if (i == 1)
      return cxx::Ref_ptr<Vmm::Mmio_device>(this);
    else if (i == 2)
      return cxx::Ref_ptr<Vmm::Mmio_device>(_prm);

    return nullptr;
  }

  cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned) override
  { return nullptr; }

  Virtio::Event_connector_msix _evcon;
};

};

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

struct Pci_controller_factory : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    Dbg info(Dbg::Dev, Dbg::Info, "proxy_ctl");
    Dbg warn(Dbg::Dev, Dbg::Warn, "proxy_ctl");

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());
    if (!pci)
      {
        warn.printf("%s: no PCI bus found\n", node.get_name());
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

    l4_size_t const max_devs = 2048;
    uint32_t dev_id = pci->bus()->alloc_dev_id();
    auto c =
      make_device<Virtio_device_proxy_control_pci>(max_devs,
                                                   devs->vmm(),
                                                   mempool,
                                                   pci->msix_dest(dev_id),
                                                   pci);

    pci->bus()->register_device(c, dev_id);

    info.printf("%s: virtio device proxy controller (PCI) registered.\n",
                node.get_name());
    info.printf("%s:  max supported devs: %zu\n",
                node.get_name(), max_devs);

    return c;
  }
};

static Pci_controller_factory pci_controller_factory;
static Vdev::Device_type pci_dt = { "virtio,pci", "device-proxy-controller",
                                    &pci_controller_factory };
}
