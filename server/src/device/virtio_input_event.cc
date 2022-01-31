/*
 * Copyright (C) 2015-2018, 2022-2024 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com> (virtio_input_power.cc)
 *            Stephan Gerhold <stephan.gerhold@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <cstring>
#include <forward_list>
#include <vector>

#include <l4/re/event>
#include <l4/re/event_enums.h>
#include <l4/re/util/event>
#include <l4/sys/cxx/ipc_epiface>

#include "device_factory.h"
#include "guest.h"
#include "mmio_device.h"
#include "virtio_input.h"

/*
 * L4Re::Event bundles events from multiple "streams" (typically devices).
 * Since virtio-input always refers to a single input device, the events from
 * L4Re::Event must be de-multiplexed to one of multiple emulated virtio-input
 * devices.
 */
namespace {
struct Event_consumer : public virtual Vdev::Dev_ref
{
  virtual ~Event_consumer() {}
  virtual void consume(L4Re::Event_buffer::Event &e) = 0;
  virtual void notify() = 0;
};

class Event_demux : public L4::Irqep_t<Event_demux>
{
public:
  explicit Event_demux(L4::Cap<L4Re::Event> cap, L4::Registry_iface &registry)
    : _cap(cap), _ev(), _consumers()
  {
    L4Re::chksys(_ev.init<L4::Irq>(cap), "Initialize event buffer");
    L4Re::chkcap(registry.register_obj(this, irq()));
  }

  L4::Cap<L4::Irq> irq() const
  { return L4::cap_reinterpret_cast<L4::Irq>(_ev.irq()); }

  unsigned num_consumers() const
  { return _consumers.size(); }

  void wait_and_discard()
  {
    L4Re::chksys(irq()->receive(), "Wait for input events");
    L4Re::Event_buffer::Event *e;
    while ((e = _ev.buffer().next()))
      e->free();
  }

  void handle_irq()
  {
    L4Re::Event_buffer::Event *e;
    while ((e = _ev.buffer().next()))
      {
        for (auto &c : _consumers)
          c->consume(*e);
        e->free();
      }
    for (auto &c : _consumers)
      c->notify();
  }

  static Event_demux &init(L4::Cap<L4Re::Event> cap, L4::Registry_iface &registry,
                           cxx::Ref_ptr<Event_consumer> consumer);

private:
  L4::Cap<L4Re::Event> _cap;
  L4Re::Util::Event _ev;
  std::vector<cxx::Ref_ptr<Event_consumer>> _consumers;

  static std::forward_list<Event_demux> _events;
};

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
} // namespace

namespace Vdev {

/**
 * Virtio input device bridge for L4Re::Event. The device reads input events
 * provided by a L4Re::Event server and forwards them with virtio-input to the
 * virtual machine.
 *
 * Example device tree:
 *
 * virtio@ff900000 {
 *     compatible = "virtio,mmio";
 *     reg = <0xff900000 0x200>;
 *     interrupts = <GIC_SPI 42 IRQ_TYPE_LEVEL_HIGH>;
 *     dma-coherent;
 *     l4vmm,vdev = "input-event";
 *     l4vmm,eventcap = "input";
 *     l4vmm,stream-id = <42>; // optional
 * };
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
: public Virtio_input<Virtio_input_event_mmio>,
  public Vmm::Ro_ds_mapper_t<Virtio_input_event_mmio>,
  public Virtio::Mmio_connector<Virtio_input_event_mmio>,
  public Event_consumer
{
public:
  Virtio_input_event_mmio(Vmm::Vm_ram *ram, L4::Cap<L4Re::Event> cap)
  : Virtio_input(ram), _cap(cap), _sinfo(), dirty(false)
  {}

  int init_irqs(Vdev::Device_lookup *devs, Vdev::Dt_node const &self)
  { return event_connector()->init_irqs(devs, self); }

  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

  long init_idx(int idx)
  { return _cap->get_stream_info(idx, &_sinfo); }
  long init_stream_id(l4_umword_t id)
  { return _cap->get_stream_info_for_id(id, &_sinfo); }

  void consume(L4Re::Event_buffer::Event &e) override
  {
    if (e.payload.stream_id != _sinfo.stream_id || !_vqs[0].ready())
      return;

    l4virtio_input_event_t event{e.payload.type, e.payload.code,
                                 static_cast<l4_uint32_t>(e.payload.value)};
    inject_event(event);
    dirty = true;
  }

  void notify() override
  {
    if (!dirty)
      return;

    notify_events();
    dirty = false;
  }

  void virtio_queue_notify(unsigned val)
  {
    // We do not handle the status queue and we do not keep pending events. So
    // we do not need to do anything if queue 0 is notified (signalling the
    // addition of buffers to the queue). We could disable notifications here
    // but are not doing it at the moment.
    if (val)
      Dbg(Dbg::Dev, Dbg::Info).printf("Pending request in queue %d\n", val);
  }

  void virtio_device_config_written(unsigned reg);

  char const *dev_name() const override { return "Virtio_input_event_mmio"; }

private:
  void virtio_input_cfg_written(l4virtio_input_config_t *dev_cfg);

  Virtio::Event_connector_irq _evcon;
  L4::Cap<L4Re::Event> _cap;
  L4Re::Event_stream_info _sinfo;
  bool dirty;
};

void
Virtio_input_event_mmio::virtio_input_cfg_written(l4virtio_input_config_t *dev_cfg)
{
  switch(dev_cfg->select)
    {
    case L4VIRTIO_INPUT_CFG_ID_NAME:
      static_assert(sizeof(dev_cfg->u.string) > sizeof(_sinfo.name),
                    "virtio name smaller than L4Re one");
      strncpy(dev_cfg->u.string, _sinfo.name, sizeof(_sinfo.name));
      dev_cfg->size = strnlen(dev_cfg->u.string, sizeof(_sinfo.name));
      break;
    case L4VIRTIO_INPUT_CFG_ID_SERIAL:
      {
        char const id[] = "1337";
        strncpy(dev_cfg->u.string, id, sizeof(dev_cfg->u.string));
        dev_cfg->size = strlen(id);
        break;
      }
    case L4VIRTIO_INPUT_CFG_ID_DEVIDS:
      dev_cfg->u.ids = { _sinfo.id.bustype, _sinfo.id.vendor,
                         _sinfo.id.product, _sinfo.id.version };
      dev_cfg->size = sizeof(l4virtio_input_devids_t);
      break;
    case L4VIRTIO_INPUT_CFG_PROP_BITS:
      memset(dev_cfg->u.bitmap, 0, sizeof(dev_cfg->u.bitmap));

      static_assert(sizeof(dev_cfg->u.bitmap) >= sizeof(_sinfo.propbits),
                    "Bitmap too small for propbits");
      memcpy(dev_cfg->u.bitmap, _sinfo.propbits, sizeof(_sinfo.propbits));
      dev_cfg->size = sizeof(dev_cfg->u.bitmap);
      break;
    case L4VIRTIO_INPUT_CFG_EV_BITS:
      memset(dev_cfg->u.bitmap, 0, sizeof(dev_cfg->u.bitmap));
      dev_cfg->size = 0;

      if (!_sinfo.get_evbit(dev_cfg->subsel))
        break;

      switch (dev_cfg->subsel)
        {
        case L4RE_EV_KEY:
          static_assert(sizeof(dev_cfg->u.bitmap) >= sizeof(_sinfo.keybits),
                        "Bitmap too small for keybits");
          memcpy(dev_cfg->u.bitmap, _sinfo.keybits, sizeof(_sinfo.keybits));
          dev_cfg->size = sizeof(dev_cfg->u.bitmap);
          break;
        case L4RE_EV_REL:
          static_assert(sizeof(dev_cfg->u.bitmap) >= sizeof(_sinfo.relbits),
                        "Bitmap too small for relbits");
          memcpy(dev_cfg->u.bitmap, _sinfo.relbits, sizeof(_sinfo.relbits));
          dev_cfg->size = sizeof(dev_cfg->u.bitmap);
          break;
        case L4RE_EV_ABS:
          static_assert(sizeof(dev_cfg->u.bitmap) >= sizeof(_sinfo.absbits),
                        "Bitmap too small for absbits");
          memcpy(dev_cfg->u.bitmap, _sinfo.absbits, sizeof(_sinfo.absbits));
          dev_cfg->size = sizeof(dev_cfg->u.bitmap);
          break;
        case L4RE_EV_SW:
          static_assert(sizeof(dev_cfg->u.bitmap) >= sizeof(_sinfo.swbits),
                        "Bitmap too small for swbits");
          memcpy(dev_cfg->u.bitmap, _sinfo.swbits, sizeof(_sinfo.swbits));
          dev_cfg->size = sizeof(dev_cfg->u.bitmap);
          break;
        }
      break;
    case L4VIRTIO_INPUT_CFG_ABS_INFO:
      dev_cfg->size = 0;
      if (!_sinfo.get_evbit(L4RE_EV_ABS) || !_sinfo.get_absbit(dev_cfg->subsel))
        break;

      {
        L4Re::Event_absinfo info{};
        unsigned int axis = dev_cfg->subsel;
        long ret = _cap->get_axis_info(_sinfo.stream_id, 1, &axis, &info);
        if (ret < 0)
          {
            Err().printf("Failed to get axis info: %ld\n", ret);
            break;
          }

        dev_cfg->u.abs.min = info.min;
        dev_cfg->u.abs.max = info.max;
        dev_cfg->u.abs.fuzz = info.fuzz;
        dev_cfg->u.abs.flat = info.flat;
        dev_cfg->u.abs.res = info.resolution;
        dev_cfg->size = sizeof(dev_cfg->u.abs);
      }
      break;
    default:
      dev_cfg->size = 0;
      break;
  }

  // flush the complete structure instead of selectively flushing the actually
  // used area
  writeback_cache(dev_cfg);
}

void
Virtio_input_event_mmio::virtio_device_config_written(unsigned reg)
{
  auto *dev_cfg = virtio_device_config<l4virtio_input_config_t>();

  switch(reg)
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
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual input device\n");
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

    auto c = make_device<Virtio_input_event_mmio>(devs->ram().get(), cap);
    if (c->init_irqs(devs, node) < 0)
      return nullptr;

    auto &demux = Event_demux::init(cap, *devs->vmm()->registry(), c);

    /*
     * virtio-mmio devices are currently not hotpluggable, which means that all
     * the information about the input device must be available before the VM
     * is started. Depending on the L4Re::Event server this might be
     * immediately or only once the first input event has been handled.
     *
     * The loops below wait until the necessary stream info are available,
     * discarding incoming events inbetween to avoid overflowing the queue.
     */
    long ret;
    if (id_prop)
      {
        auto id = fdt32_to_cpu(*id_prop);
        while ((ret = c->init_stream_id(id)) == -L4_EINVAL)
          demux.wait_and_discard();
      }
    else
      {
        // Use next index number
        while ((ret = c->init_idx(demux.num_consumers() - 1)) == -L4_EINVAL)
          demux.wait_and_discard();
      }
    L4Re::chksys(ret, "Initialize event stream info");

    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);
    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "input-event", &f };

}
