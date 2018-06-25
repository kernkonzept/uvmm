/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <l4/re/env>
#include <l4/cxx/static_vector>

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "pci_bus.h"
#include "ds_mmio_mapper.h"
#include "pci_virtio_device.h"
#include "virtio_pci_connector.h"
#include "virtio_console.h"
#include "event_connector_pci.h"

class Virtio_console_pci
: public Vdev::Virtio_console<Virtio_console_pci>,
  public Vdev::Virtio_device_pci<Virtio_console_pci>,
  public Virtio::Pci_connector<Virtio_console_pci>
{
public:
  Virtio_console_pci(Vmm::Vm_ram *iommu, L4::Cap<L4::Vcon> con,
                     cxx::Ref_ptr<Gic::Msi_distributor> distr,
                     unsigned num_msix_entries)
  : Virtio_console(iommu, con),
    Virtio_device_pci<Virtio_console_pci>(),
    Virtio::Pci_connector<Virtio_console_pci>(),
    _evcon(distr, num_msix_entries)
  {
  }

  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

private:
  Virtio::Event_connector_msix _evcon;
};

namespace {

using namespace Vdev;

struct F : Factory
{
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "VIO Cons"); }

  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    info().printf("Create virtual PCI console\n");
    l4_uint64_t dt_msi_base = 0, dt_msi_size = 0;
    node.get_reg_val(0, &dt_msi_base, &dt_msi_size);

    l4_uint64_t dt_base = 0;
    l4_uint64_t dt_size = 0;
    Pci_device::dt_get_untranslated_reg_val(node, 1, &dt_base, &dt_size);

    info().printf("Console base & size: 0x%llx, 0x%llx\nMSI-X memory address & "
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

    auto *pci = dynamic_cast<Pci_bus_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("No PCI bus found.\n");
        return nullptr;
      }

    auto io_apic = devs->device_from_node(node.find_irq_parent());
    auto msi_distr = cxx::dynamic_pointer_cast<Gic::Msi_distributor>(io_apic);

    if (!msi_distr)
      L4Re::chksys(-L4_EINVAL, "IO-APIC is the IRQ parent of the device.");

    auto vmm = devs->vmm();
    int const num_msix = 5;
    auto console = make_device<Virtio_console_pci>(devs->ram().get(),
                                                   L4Re::Env::env()->log(),
                                                   msi_distr, num_msix);
    if (console->init_irqs(devs, node) < 0)
      return nullptr;

    vmm->register_io_device(Region::ss(regs[1].base, regs[1].size), console);
    console->register_obj(vmm->registry());
    console->configure(regs, num_msix);
    pci->register_device(console);

    info().printf("Console: %p\n", console.get());

    return console;
  }
}; // struct F

static F f;
static Device_type t = {"virtio,pci", "console", &f};

} // namespace
