/*
 * Copyright (C) 2023-2024 Kernkonzept GmbH.
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

enum
{
  Cfg_bar = 1,
  L4Cfg_bar = 2
};

/**
 * PCI Virtio proxy for a device exported from the VMM.
 *
 * PCI Device for emulating a virtio device for the guest. Needs a special l4
 * driver running within the guest os.
 *
 * A device tree entry needs to look like this:
 *
 * pci0: pci@aa000000 {
 *     compatible = "virt-pci-bridge";
 *     ...
 *     ranges = <0x01000000 0x0 0x00006000 0x0 0x00006000 0x0     0xa000
 *               0x02000000 0x0 0x8a000000 0x0 0x8a000000 0x0 0x20000000
 *               0x03000000 0x2 0x00000000 0x2 0x00000000 0x1 0x00000000>;
 *     ...
 *     virtio_dev_proxy@3 {
 *        compatible = "virtio,pci";
 *        // The reg property requirements are described in virtio_uart. The
 *        // third row holds the virtio config space. The forth row is for the l4
 *        // config space.
 *        reg = <0x00001800 0x0 0x0 0x0 0x0000
 *               0x02001810 0x0 0x0 0x0 0x2000
 *               0x02001814 0x0 0x0 0x0 0x1000
 *               0x02001818 0x0 0x0 0x0 0x1000>;
 *        msi-parent = <&msi_ctrl>;
 *        l4vmm,virtiocap = "viodev";
 *        l4vmm,vdev = "device-proxy";
 *        l4vmm,mempool = <&viodev_mp>;
 *     }
 *     ...
 * }
 *
 * viodev_mp points to the node containing the memory pool for the foreign
 * guest memory. See the virtio mem pool documentation for details.
 */
class Virtio_device_proxy_pci
: public Pci::Virt_pci_device,
  public Virtio_device_proxy_base
{
  struct L4host_pci_cap : Pci::Vendor_specific_cap
  {
    explicit L4host_pci_cap()
    : Vendor_specific_cap(sizeof(*this))
    {}

    l4_uint8_t cfg_type = 1;
    l4_uint8_t cfg_bar;
    l4_uint8_t l4cfg_bar;
  };

  enum
  {
    // PCI device id is L4Re specific
    Virtio_pci_device_id_vhost = 50
  };

public:
  Virtio_device_proxy_pci(Vdev::Dt_node const &node,
                          unsigned num_msix_entries,
                          Gic::Msix_dest const &msix_dest,
                          Vdev::Pci::Pci_bridge_windows *wnds,
                          L4::Cap<L4::Rcv_endpoint> ep,
                          l4_size_t cfg_size, l4_uint64_t l4cfg_size,
                          Vmm::Guest *vmm,
                          cxx::Ref_ptr<Virtio_device_mem_pool> mempool)
  : Pci::Virt_pci_device(node, wnds),
    Virtio_device_proxy_base(ep, cfg_size, l4cfg_size, vmm, mempool),
    _evcon(msix_dest)
  {
    Pci_msix_cap *cap    = create_pci_cap<Pci_msix_cap>();
    cap->ctrl.enabled()  = 1;
    cap->ctrl.masked()   = 0;
    cap->ctrl.max_msis() = num_msix_entries - 1;
    cap->tbl.bir()       = 0;
    cap->pba.offset()    = L4_PAGESIZE >> 3;
    cap->pba.bir()       = 0;

    L4host_pci_cap *cap1 = create_pci_cap<L4host_pci_cap>();
    cap1->cfg_bar = Cfg_bar;
    cap1->l4cfg_bar = L4Cfg_bar;

    auto * const hdr = get_header<Pci_header::Type0>();
    hdr->vendor_id = Virtio_pci_device_vendor_id;
    // PCI device_id is calculated by Virtio Device ID + 0x1040
    // (see virtio 1.0 cs4)
    hdr->device_id = Virtio_pci_device_id_base + Virtio_pci_device_id_vhost;
    hdr->revision_id = Non_transitional_device_pci_revision_id;
    hdr->subsystem_id = Virtio_pci_subsystem_id_minimum;
    // hdr->subsystem_id && hdr->subsystem_vendor: virtio spec 1.0 cs4: optional
    hdr->status = Interrupt_status_bit | Capability_list_bit;
    hdr->header_type = Multi_func_bit;
    hdr->classcode[2] = Pci_class_code_other_device;
  }

private:
  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

  void irq_kick() override
  { _evcon.send_event(0); }

  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned i) override
  {
    if (i == 0)
      return event_connector()->make_mmio_device();
    else if (i == Cfg_bar)
      return cxx::Ref_ptr<Vmm::Mmio_device>(this);
    else if (i == L4Cfg_bar)
      return cxx::Ref_ptr<Vmm::Mmio_device>(_l4cfg.ds_hdlr);

    return nullptr;
  }

  cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned) override
  { return nullptr; }

  Virtio::Event_connector_msix _evcon;
};

} // namespace Vdev

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

struct Pci_factory : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    Dbg info(Dbg::Dev, Dbg::Info, "VioDevProxy");
    Dbg warn(Dbg::Dev, Dbg::Warn, "VioDevProxy");

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());
    if (!pci)
      {
        warn.printf("%s: no PCI bus found\n", node.get_name());
        return nullptr;
      }

    auto cap = Vdev::get_cap<L4::Rcv_endpoint>(node, "l4vmm,virtiocap");
    if (!cap)
      {
        warn.printf("%s: failed to read 'l4vmm,virtiocap'\n", node.get_name());
        return nullptr;
      }

    l4_uint64_t cfg_size;
    Dtb::Reg_flags cfg_flags;
    auto res = node.get_reg_size_flags(Cfg_bar + 1, &cfg_size, &cfg_flags);
    if (res < 0)
      {
        warn.printf("%s: failed to read 'reg[%u] = virtio cfg': %s\n",
                      node.get_name(), Cfg_bar + 1, node.strerror(res));
        return nullptr;
      }

    if (!cfg_flags.is_mmio())
      {
        warn.printf("%s: virtio cfg bar must be mmio\n", node.get_name());
        return nullptr;
      }

    l4_uint64_t l4cfg_size;
    Dtb::Reg_flags l4cfg_flags;
    res = node.get_reg_size_flags(L4Cfg_bar + 1, &l4cfg_size, &l4cfg_flags);
    if (res < 0)
      {
        warn.printf("%s: failed to read 'reg[%u] = l4 cfg': %s\n",
                    node.get_name(), L4Cfg_bar + 1, node.strerror(res));
        return nullptr;
      }

    if (!l4cfg_flags.is_mmio())
      {
        warn.printf("%s: l4 cfg bar must be mmio\n", node.get_name());
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

    auto dev_id = pci->bus()->alloc_dev_id();
    unsigned num_msix = 1;
    auto c =
      make_device<Virtio_device_proxy_pci>(node, num_msix,
                                           pci->msix_dest(dev_id),
                                           pci->bridge_windows(),
                                           cap,
                                           cfg_size, l4cfg_size,
                                           devs->vmm(),
                                           mempool);

    pci->bus()->register_device(c, dev_id);

    info.printf("%s: virtio device proxy (PCI) registered\n", node.get_name());
    return c;
  }
};

static Pci_factory pci_factory;
static Vdev::Device_type pci_dt = { "virtio,pci", "device-proxy", &pci_factory };
}
