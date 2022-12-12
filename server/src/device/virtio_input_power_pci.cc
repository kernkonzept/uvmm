/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 *            Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */

#include "pci_device.h"
#include "pci_virtio_device.h"
#include "pci_host_bridge.h"
#include "virtio_pci_connector.h"
#include "event_connector_pci.h"
#include "virtio_input_power.h"

namespace Vdev {

struct Virtio_input_power_pci
: public Virtio_input<Virtio_input_power_pci>,
  public Virtio_input_power<Virtio_input_power_pci>,
  public Pci::Virtio_device_pci<Virtio_input_power_pci>,
  public Virtio::Pci_connector<Virtio_input_power_pci>
{
  explicit Virtio_input_power_pci(Vdev::Dt_node const &node,
                                  unsigned num_msix_entries, Vmm::Vm_ram *ram,
                                  L4::Cap<L4::Vcon> con,
                                  Gic::Msix_dest const &msix_dest,
                                  Vdev::Pci::Pci_bridge_windows *wnds)
  : Virtio_input(ram),
    Virtio_input_power(con),
    Virtio_device_pci<Virtio_input_power_pci>(node, num_msix_entries, wnds),
    Virtio::Pci_connector<Virtio_input_power_pci>(),
    _evcon(msix_dest)
  {
    init_virtio_pci_device();
    if (device_config_len() < sizeof(l4virtio_input_config_t))
      L4Re::throw_error(-L4_EINVAL, "device config can hold input cfg");
  }

  Virtio::Event_connector_msix *event_connector() { return &_evcon; }

  int inject_events(l4virtio_input_event_t *events, size_t num)
  { return Virtio_input<Virtio_input_power_pci>::inject_events(events, num); }

  void virtio_pci_device_config_written()
  {
    l4virtio_input_config_t *dev_cfg = virtio_device_config<l4virtio_input_config_t>();
    virtio_input_cfg_written(dev_cfg);
  }

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

} // namespace Vdev

namespace {

using namespace Vdev;
using namespace Vdev::Pci;

struct Pci_factory : Factory
{
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "Input-pci"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "Input-pci"); }

  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual input device (Pci factory)\n");

    auto *pci = dynamic_cast<Pci_host_bridge *>(
      devs->device_from_node(node.parent_node()).get());

    if (!pci)
      {
        info().printf("No PCI bus found.\n");
        return nullptr;
      }

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,vcon_cap");
    if (!cap)
      return nullptr;

    auto dev_id = pci->bus()->alloc_dev_id();
    unsigned num_msix = 5;
    auto input =
      make_device<Virtio_input_power_pci>(node, num_msix, devs->ram().get(),
                                          cap, pci->msix_dest(dev_id),
                                          pci->bridge_windows());

    input->register_obj(devs->vmm()->registry());
    pci->bus()->register_device(input, dev_id);

    info().printf("Input-power registered\n");
    return input;
  }
};

static Pci_factory pci_factory;
static Vdev::Device_type pci_dt = { "virtio,pci", "input-power", &pci_factory };
}
