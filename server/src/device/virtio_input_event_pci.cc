/*
 * Copyright (C) 2024 Kernkonzept GmbH.
 * Author(s): Martin Decky <martin.decky@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "pci_device.h"
#include "pci_virtio_device.h"
#include "pci_host_bridge.h"
#include "virtio_pci_connector.h"
#include "event_connector_pci.h"
#include "virtio_input_event.h"

namespace Vdev {

/**
 * Virtio input device bridge for L4Re::Event. The device reads input events
 * provided by a L4Re::Event server and forwards them with virtio-input to the
 * virtual machine.
 *
 * Example device tree:
 *
 * \code{.dtb}
 *   virtio@0 {
 *       compatible = "virtio,pci";
 *       reg = <0x00000800 0x0 0x0 0x0 0x0000
 *              0x02000810 0x0 0x0 0x0 0x2000
 *              0x01000814 0x0 0x0 0x0 0x100>;
 *       msi-parent = <&msi_ctrl>;
 *       l4vmm,vdev = "input-event";
 *       l4vmm,eventcap = "input";
 *       l4vmm,stream-id = <42>; // optional
 *   };
 * \endcode
 *
 * 'l4vmm,eventcap' must point to the name of the L4Re::Event capability
 * (or L4Re::Console if it is provided by a framebuffer server). Each virtio
 * input device can only forward events from one stream provided by the
 * L4Re::Event server (typically there is one stream for each input device,
 * such as mouse and keyboard).
 *
 * 'l4vmm,stream-id' can be used to configure a specific input stream based
 * on its stream ID. If omitted, the virtio input device is assigned the next
 * unused stream of the event capability.
 *
 * Since virtio input devices are currently not hotpluggable, uvmm needs to
 * wait during startup until all specified input devices are available.
 */
class Virtio_input_event_pci
: public Virtio_input_event<Virtio_input_event_pci>,
  public Virtio_input<Virtio_input_event_pci>,
  public Pci::Virtio_device_pci<Virtio_input_event_pci>,
  public Virtio::Pci_connector<Virtio_input_event_pci>
{
public:
  explicit Virtio_input_event_pci(Vdev::Dt_node const &node,
                                  unsigned num_msix_entries, Vmm::Vm_ram *ram,
                                  L4::Cap<L4Re::Event> cap,
                                  Gic::Msix_dest const &msix_dest,
                                  Vdev::Pci::Pci_bridge_windows *wnds)
  : Virtio_input_event<Virtio_input_event_pci>(cap),
    Virtio_input<Virtio_input_event_pci>(ram),
    Virtio_device_pci<Virtio_input_event_pci>(node, num_msix_entries, wnds),
    Virtio::Pci_connector<Virtio_input_event_pci>(),
    _evcon(msix_dest)
  {
    init_virtio_pci_device();
    if (device_config_len() < sizeof(l4virtio_input_config_t))
      L4Re::throw_error(-L4_EINVAL, "device config can hold input cfg");
  }

  Virtio::Event_connector_msix *event_connector()
  { return &_evcon; }

  bool queue_ready()
  { return _vqs[0].ready(); }

  void virtio_device_config_written(unsigned)
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
  static Dbg info() { return Dbg(Dbg::Dev, Dbg::Info, "Input-event-pci"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "Input-event-pci"); }

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

    auto cap = get_cap<L4Re::Event>(node, "l4vmm,eventcap");
    if (!cap)
      return nullptr;

    int prop_size;
    auto id_prop = node.get_prop<fdt32_t>("l4vmm,stream-id", &prop_size);
    if (id_prop && prop_size != 1)
      {
        Err().printf("Invalid l4vmm,stream-id property size: %d\n", prop_size);
        return nullptr;
      }

    auto dev_id = pci->bus()->alloc_dev_id();
    unsigned num_msix = 5;
    auto dev =
      make_device<Virtio_input_event_pci>(node, num_msix, devs->ram().get(),
                                          cap, pci->msix_dest(dev_id),
                                          pci->bridge_windows());

    dev->init_demux(cap, devs, dev, id_prop);
    pci->bus()->register_device(dev, dev_id);

    info().printf("Input-event registered\n");
    return dev;
  }
};

static Pci_factory pci_factory;
static Vdev::Device_type pci_dt = { "virtio,pci", "input-event", &pci_factory };

} // namespace
