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
  Virtio_console_pci(Vdev::Dt_node const &node, unsigned num_msix_entries,
                     Vmm::Vm_ram *ram, L4::Cap<L4::Vcon> con,
                     Gic::Msix_dest const &msix_dest)
  : Virtio_console(ram, con),
    Virtio_device_pci<Virtio_console_pci>(node, num_msix_entries),
    Virtio::Pci_connector<Virtio_console_pci>(),
    _evcon(msix_dest)
  {
    init_virtio_pci_device();
  }

  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

protected:
  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_bar_handler(unsigned) override
  {
    return event_connector()->make_mmio_device();
  }

  cxx::Ref_ptr<Vmm::Io_device> get_io_bar_handler(unsigned) override
  {
    return cxx::Ref_ptr<Vmm::Io_device>(this);
  }

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

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("No PCI bus found.\n");
        return nullptr;
      }

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,virtiocap",
                                       L4Re::Env::env()->log());
    if (!cap)
      return nullptr;

    auto dev_id = pci->alloc_dev_id();
    unsigned num_msix = 5;
    auto console =
      make_device<Virtio_console_pci>(node, num_msix, devs->ram().get(), cap,
                                      pci->msix_dest(dev_id));

    console->register_obj(devs->vmm()->registry());
    pci->register_device(console, dev_id);

    info().printf("Console: %p\n", console.get());

    return console;
  }
}; // struct F

static F f;
static Device_type t = {"virtio,pci", "console", &f};

} // namespace
