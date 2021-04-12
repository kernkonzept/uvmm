/*
 * Copyright (C) 2017 Kernkonzept GmbH.
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
: public Vdev::Virtio_proxy<Virtio_proxy_pci>,
  public Vdev::Pci::Virtio_device_pci<Virtio_proxy_pci>,
  public Virtio::Pci_connector<Virtio_proxy_pci>
{
public:
  Virtio_proxy_pci(L4::Cap<L4virtio::Device> device, l4_uint64_t config_sz,
                   unsigned nnq_id, Vmm::Vm_ram *ram,
                   cxx::Ref_ptr<Gic::Msix_controller> distr)
  : Virtio_proxy<Virtio_proxy_pci>(device, config_sz, nnq_id, ram),
    Virtio_device_pci<Virtio_proxy_pci>(),
    Virtio::Pci_connector<Virtio_proxy_pci>(),
    _evcon(distr)
  {}

  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

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

    l4_uint64_t dt_msi_base = 0, dt_msi_size = 0;
    node.get_reg_val(0, &dt_msi_base, &dt_msi_size);

    l4_uint64_t dt_base = 0, dt_size = 0;
    Virt_pci_device::dt_get_untranslated_reg_val(node, 1, &dt_base, &dt_size);

    info().printf("Proxy base & size 0x%llx, 0x%llx\nMSI-X memory address & "
                  "size: 0x%llx, 0x%llx\n",
                  dt_base, dt_size, dt_msi_base, dt_msi_size);

    check_dt_io_mmio_constraints(dt_msi_base, dt_msi_size, dt_base, dt_size);

    l4_size_t cfgsz = dt_size - Num_pci_connector_ports;
    warn().printf("cfgsize is 0x%lx\n", cfgsz);

    Device_register_entry regs[] =
      {{dt_msi_base, dt_msi_size, Virt_pci_device::dt_get_reg_flags(node, 0)},
       {dt_base, dt_size, Virt_pci_device::dt_get_reg_flags(node, 1)}};

    check_dt_regs_flag(regs);

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("VirtIO proxy: No PCI bus found.\n");
        return nullptr;
      }

    auto msi_distr = devs->get_or_create_mc_dev(node);
    Dbg().printf("Msi controller %p\n", msi_distr.get());

    int sz;
    unsigned nnq_id = -1U;
    auto const *prop = node.get_prop<fdt32_t>("l4vmm,no-notify", &sz);
    if (prop && sz > 0)
      nnq_id = fdt32_to_cpu(*prop);

    auto vmm = devs->vmm();

    // cfgsz + 0x100 => DT tells dev config size; add virtio config hdr
    auto proxy =
      make_device<Virtio_proxy_pci>(cap, cfgsz + 0x100, nnq_id, devs->ram().get(),
                                    msi_distr);

    if (proxy->init_irqs(devs, node) < 0)
      return nullptr;

    if (regs[1].flags & Dt_pci_flags_io)
      {
        auto region = Vmm::Io_region::ss(regs[1].base, regs[1].size,
                                         Vmm::Region_type::Virtual);
        vmm->register_io_device(region, proxy);
      }

    proxy->register_irq(vmm->registry());

    // Only two MSIs (config & VQ). l4virtio supports only shared IRQs for all
    // VQs.
    int const num_msix = 2;
    proxy->configure(regs, num_msix, cfgsz);
    pci->register_device(proxy);

    return proxy;
  }
};

static F f;
static Device_type t = { "virtio,pci", "proxy", &f };

} // namespace
