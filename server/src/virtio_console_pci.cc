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
#include "ds_mmio_mapper.h"
#include "pci_virtio_device.h"
#include "virtio_pci_connector.h"
#include "virtio_console.h"
#include "event_connector_pci.h"
#include "device/pci_host_bridge.h"

class Virtio_console_pci
: public Vdev::Virtio_console<Virtio_console_pci>,
  public Vdev::Pci::Virtio_device_pci<Virtio_console_pci>,
  public Virtio::Pci_connector<Virtio_console_pci>
{
public:
  Virtio_console_pci(Vmm::Vm_ram *ram, L4::Cap<L4::Vcon> con,
                     cxx::Ref_ptr<Gic::Msix_controller> distr)
  : Virtio_console(ram, con),
    Virtio_device_pci<Virtio_console_pci>(),
    Virtio::Pci_connector<Virtio_console_pci>(),
    _evcon(distr)
  {
  }

  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

private:
  Virtio::Event_connector_msix _evcon;
};

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

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
    Virt_pci_device::dt_get_untranslated_reg_val(node, 1, &dt_base, &dt_size);

    info().printf("Console base & size: 0x%llx, 0x%llx\nMSI-X memory address & "
                  "size: 0x%llx, 0x%llx\n",
                  dt_base, dt_size, dt_msi_base, dt_msi_size);

    check_dt_io_mmio_constraints(dt_msi_base, dt_msi_size, dt_base, dt_size);

    Device_register_entry regs[] =
      {{dt_msi_base, dt_msi_size, Virt_pci_device::dt_get_reg_flags(node, 0)},
       {dt_base, dt_size, Virt_pci_device::dt_get_reg_flags(node, 1)}};

    check_dt_regs_flag(regs);

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("No PCI bus found.\n");
        return nullptr;
      }

    auto msi_distr = devs->get_or_create_mc_dev(node);
    Dbg().printf("Msix controller %p\n", msi_distr.get());

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,virtiocap",
                                       L4Re::Env::env()->log());
    if (!cap)
      return nullptr;

    auto vmm = devs->vmm();
    auto console = make_device<Virtio_console_pci>(devs->ram().get(), cap,
                                                   msi_distr);
    if (console->init_irqs(devs, node) < 0)
      return nullptr;

    vmm->register_io_device(Vmm::Io_region::ss(regs[1].base, regs[1].size,
                                               Vmm::Region_type::Virtual),
                            console);
    console->register_obj(vmm->registry());
    unsigned num_msix = 5;
    console->configure(regs, num_msix);
    pci->register_device(console);

    info().printf("Console: %p\n", console.get());

    return console;
  }
}; // struct F

static F f;
static Device_type t = {"virtio,pci", "console", &f};

} // namespace
