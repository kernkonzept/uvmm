/*
 * Copyright (C) 2015-2018, 2022-2024 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com> (virtio_input_power.cc)
 *            Stephan Gerhold <stephan.gerhold@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <cstring>
#include <forward_list>

#include <l4/re/event>
#include <l4/re/event_enums.h>
#include <l4/re/util/event>
#include <l4/sys/cxx/ipc_epiface>

#include "device_factory.h"
#include "guest.h"
#include "mmio_device.h"
#include "virtio_input.h"

#include "virtio_input_event.h"

namespace Vdev {

Event_demux &
Event_demux::init(L4::Cap<L4Re::Event> cap, L4::Registry_iface &registry,
                  cxx::Ref_ptr<Event_consumer> consumer)
{
  auto it = std::find_if(_events.begin(), _events.end(),
                         [cap] (Event_demux &d) { return d._cap == cap; });
  if (it == _events.end())
    {
      _events.emplace_front(cap, registry);
      it = _events.begin();
    }

  it->_consumers.emplace_back(consumer);
  return *it;
}

std::forward_list<Event_demux> Event_demux::_events;

/**
 * Virtio input device bridge for L4Re::Event. The device reads input events
 * provided by a L4Re::Event server and forwards them with virtio-input to the
 * virtual machine.
 *
 * Example device tree:
 *
 * \code{.dtb}
 *   virtio@ff900000 {
 *       compatible = "virtio,mmio";
 *       reg = <0xff900000 0x200>;
 *       interrupts = <GIC_SPI 42 IRQ_TYPE_LEVEL_HIGH>;
 *       dma-coherent;
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
class Virtio_input_event_mmio
: public Virtio_input_event<Virtio_input_event_mmio>,
  public Virtio_input<Virtio_input_event_mmio>,
  public Vmm::Mmio_device_t<Virtio_input_event_mmio>,
  public Virtio::Mmio_connector<Virtio_input_event_mmio>
{
public:
  explicit Virtio_input_event_mmio(Vmm::Vm_ram *ram, L4::Cap<L4Re::Event> cap)
  : Virtio_input_event<Virtio_input_event_mmio>(cap),
    Virtio_input<Virtio_input_event_mmio>(ram)
  {}

  Virtio::Event_connector_irq *event_connector()
  { return &_evcon; }

  bool queue_ready()
  { return _vqs[0].ready(); }

  void virtio_device_config_written(unsigned reg)
  {
    auto *dev_cfg = virtio_device_config<l4virtio_input_config_t>();

    switch (reg)
      {
      case 0:
        break;
      case 1:
        virtio_input_cfg_written(dev_cfg);
        break;
      default:
        Dbg(Dbg::Dev, Dbg::Warn, "input")
          .printf("%s: Unexpected reg %d written\n", __func__, reg);
      }
  }

  char const *dev_name() const override
  { return "Virtio_input_event_mmio"; }

private:
  Virtio::Event_connector_irq _evcon;
};

} // namespace Vdev

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual input event device (Mmio_factory)\n");
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

    auto dev = make_device<Virtio_input_event_mmio>(devs->ram().get(), cap);
    if (dev->init_irqs(devs, node) < 0)
      return nullptr;

    dev->init_demux(cap, devs, dev, id_prop);
    devs->vmm()->register_mmio_device(dev, Vmm::Region_type::Virtual, node);
    return dev;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "input-event", &f };

}
