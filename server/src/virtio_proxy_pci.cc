/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/cxx/static_vector>

#include "virtio_pci_connector.h"
#include "event_connector_pci.h"
#include "pci_virtio_device.h"
#include "virtio_proxy.h"
#include "device/pci_host_bridge.h"


class Virtio_proxy_pci
: public Vdev::Pci::Virtio_device_pci<Virtio_proxy_pci>,
  public Vdev::Virtio_proxy<Virtio_proxy_pci>,
  public Virtio::Pci_connector<Virtio_proxy_pci>
{
public:
  Virtio_proxy_pci(Vdev::Dt_node const &node, unsigned num_msix_entries,
                   L4::Cap<L4virtio::Device> device,
                   unsigned nnq_id, Vmm::Vm_ram *ram,
                   Gic::Msix_dest const &msix_dest,
                   Vdev::Pci::Pci_bridge_windows *wnds)
  : Virtio_device_pci<Virtio_proxy_pci>(node, num_msix_entries, wnds),
    // 0x100: size of the virtio config header
    Virtio_proxy<Virtio_proxy_pci>(device, 0x100 + device_config_len(), nnq_id, ram),
    Virtio::Pci_connector<Virtio_proxy_pci>(),
    _evcon(msix_dest)
  {}

  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

  void virtio_pci_device_config_written() {}

protected:
  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned idx) override
  {
    if (idx == 0)
      return event_connector()->make_mmio_device();

    return cxx::Ref_ptr<Vmm::Mmio_device>(this);
  }

  cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned) override
  {
    return cxx::Ref_ptr<Vmm::Io_device>(this);
  }

private:
  Virtio::Event_connector_msix _evcon;
};

#include "device_factory.h"
#include "pci_device.h"
#include "guest.h"
#include "ds_mmio_mapper.h"

#include <l4/re/util/cap_alloc>
#include <l4/re/dataspace>

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

struct F : Factory
{
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "VIO proxy"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "VIO proxy"); }

  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    info().printf("Creating proxy\n");

    auto cap = Vdev::get_cap<L4virtio::Device>(node, "l4vmm,virtiocap");
    if (!cap)
      return nullptr;

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("VirtIO proxy: No PCI bus found.\n");
        return nullptr;
      }

    int sz;
    unsigned nnq_id = -1U;
    auto const *prop = node.get_prop<fdt32_t>("l4vmm,no-notify", &sz);
    if (prop && sz > 0)
      nnq_id = fdt32_to_cpu(*prop);

    auto vmm = devs->vmm();

    // Only two MSIs (config & VQ). l4virtio supports only shared IRQs for all
    // VQs.
    auto dev_id = pci->bus()->alloc_dev_id();
    int const num_msix = 2;
    auto proxy =
      make_device<Virtio_proxy_pci>(node, num_msix, cap, nnq_id,
                                    devs->ram().get(), pci->msix_dest(dev_id),
                                    pci->bridge_windows());

    proxy->register_irq(vmm->registry());
    proxy->init_virtio_pci_device();
    pci->bus()->register_device(proxy, dev_id);

    return proxy;
  }
};

static F f;
static Device_type t = { "virtio,pci", "proxy", &f };

} // namespace
