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
#include "pci_bus.h"


class Virtio_proxy_pci
: public Vdev::Virtio_proxy<Virtio_proxy_pci>,
  public Vdev::Virtio_device_pci<Virtio_proxy_pci>,
  public Virtio::Pci_connector<Virtio_proxy_pci>
{
public:
  Virtio_proxy_pci(L4::Cap<L4virtio::Device> device, l4_uint64_t config_sz,
                   unsigned nnq_id, Vmm::Ram_ds *ram,
                   cxx::Ref_ptr<Gic::Msi_distributor> distr,
                   unsigned num_msix_entries)
  : Virtio_proxy<Virtio_proxy_pci>(device, config_sz, nnq_id, ram),
    Virtio_device_pci<Virtio_proxy_pci>(),
    Virtio::Pci_connector<Virtio_proxy_pci>(),
    _evcon(distr, num_msix_entries)
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

struct F : Factory
{
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "VIO proxy"); }
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "VIO proxy"); }

  static L4::Cap<L4virtio::Device> device_cap(Dt_node const &node)
  {
    int cap_name_len;
    char const *cap_name = node.get_prop<char>("l4vmm,virtiocap", &cap_name_len);
    if (!cap_name)
      {
        warn().printf(
          "'l4vmm,virtiocap' property missing for virtio proxy device.\n");
        return L4::Cap<void>::Invalid;
      }

    cap_name_len = strnlen(cap_name, cap_name_len);

    auto cap =
      L4Re::Env::env()->get_cap<L4virtio::Device>(cap_name, cap_name_len);
    if (!cap)
      {
        warn()
          .printf("'l4vmm,virtiocap' property: capability %.*s is invalid.\n",
                  cap_name_len, cap_name);
        return L4::Cap<void>::Invalid;
      }

    return cap;
  }

  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    info().printf("Creating proxy\n");

    auto cap = device_cap(node);
    if (!cap.is_valid())
      return nullptr;

    l4_uint64_t dt_msi_base = 0, dt_msi_size = 0;
    node.get_reg_val(0, &dt_msi_base, &dt_msi_size);

    l4_uint64_t dt_base = 0, dt_size = 0;
    Pci_device::dt_get_untranslated_reg_val(node, 1, &dt_base, &dt_size);

    info().printf("Proxy base & size 0x%llx, 0x%llx\nMSI-X memory address & "
                  "size: 0x%llx, 0x%llx\n",
                  dt_base, dt_size, dt_msi_base, dt_msi_size);

    // PCI BARs handle 32bit addresses only.
    if (   ((dt_base >> 32) != 0) && ((dt_size >> 32) != 0)
        && ((dt_msi_base >> 32) != 0))
      L4Re::chksys(-L4_EINVAL, "Device memory above 4GB not supported.");

    if (dt_msi_size < Msix_mem_need)
      L4Re::chksys(-L4_EINVAL, "Insufficient MSI-X memory specified.");

    Device_register_entry regs[] =
      {{dt_msi_base, dt_msi_size, Pci_device::dt_get_reg_flags(node, 0)},
       {dt_base, dt_size, Pci_device::dt_get_reg_flags(node, 1)}};

    if (!(regs[0].flags & Dt_pci_flags_mmio32))
      L4Re::chksys(-L4_EINVAL, "First DT register entry is a MMIO(32) entry.");

    if (!(regs[1].flags & Dt_pci_flags_io))
      L4Re::chksys(-L4_EINVAL, "Second DT register entry is an IO entry.");

    l4_uint64_t dummy, cfgsz;
    int res = node.get_reg_val(2, &dummy, &cfgsz);
    if (res < 0)
      {
        warn().printf("cfgsize not found, default to L4_PAGESIZE\n");
        cfgsz = L4_PAGESIZE;
      }

    auto *pci = dynamic_cast<Pci_bus_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("VirtIO proxy: No PCI bus found.\n");
        return nullptr;
      }

    auto io_apic = devs->device_from_node(node.find_irq_parent());
    auto msi_distr = cxx::dynamic_pointer_cast<Gic::Msi_distributor>(io_apic);

    if (!msi_distr)
      L4Re::chksys(-L4_EINVAL, "IO-APIC is the IRQ parent of the device.");

    int sz;
    unsigned nnq_id = -1U;
    auto const *prop = node.get_prop<fdt32_t>("l4vmm,no-notify", &sz);
    if (prop && sz > 0)
      nnq_id = fdt32_to_cpu(*prop);

    auto vmm = devs->vmm();
    int const num_msix = 10;
    auto proxy =
      make_device<Virtio_proxy_pci>(cap, cfgsz, nnq_id, devs->ram().get(),
                                    msi_distr, num_msix);

    if (regs[1].flags & Dt_pci_flags_io)
      vmm->register_io_device(Region::ss(regs[1].base, regs[1].size), proxy);

    proxy->register_irq(devs->vmm()->registry());
    proxy->configure(regs, num_msix);
    pci->register_device(proxy);

    return proxy;
  }
};

static F f;
static Device_type t = { "virtio,pci", "proxy", &f };

} // namespace

