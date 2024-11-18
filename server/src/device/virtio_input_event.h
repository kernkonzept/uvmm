/*
 * Copyright (C) 2015-2018, 2022-2024 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com> (virtio_input_power.cc)
 *            Stephan Gerhold <stephan.gerhold@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <cstring>
#include <forward_list>
#include <vector>

#include <l4/re/event>
#include <l4/re/event_enums.h>
#include <l4/re/util/event>
#include <l4/sys/cxx/ipc_epiface>

#include "virtio_input.h"

namespace Vdev {

/*
 * L4Re::Event bundles events from multiple "streams" (typically devices).
 * Since virtio-input always refers to a single input device, the events from
 * L4Re::Event must be de-multiplexed to one of multiple emulated virtio-input
 * devices.
 */

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

template <typename DEV>
class Virtio_input_event
: public Event_consumer
{
public:
  Virtio_input_event(L4::Cap<L4Re::Event> cap)
  : _cap(cap), _sinfo(), dirty(false)
  {}

  int init_irqs(Vdev::Device_lookup *devs, Vdev::Dt_node const &self)
  { return dev()->event_connector()->init_irqs(devs, self); }

  void init_demux(L4::Cap<L4Re::Event> cap, Device_lookup *devs,
                  cxx::Ref_ptr<Event_consumer> consumer,
                  fdt32_t const *id_prop);

  void consume(L4Re::Event_buffer::Event &e) override;
  void notify() override;

  void virtio_queue_notify(unsigned val)
  {
    // We do not handle the status queue and we do not keep pending events. So
    // we do not need to do anything if queue 0 is notified (signalling the
    // addition of buffers to the queue). We could disable notifications here
    // but are not doing it at the moment.
    if (val)
      Dbg(Dbg::Dev, Dbg::Info).printf("Pending request in queue %u\n", val);
  }

  bool queue_ready();

protected:
  void virtio_input_cfg_written(l4virtio_input_config_t *dev_cfg);

private:
  DEV *dev()
  { return static_cast<DEV *>(this); }

  long init_idx(int idx)
  { return _cap->get_stream_info(idx, &_sinfo); }

  long init_stream_id(l4_umword_t id)
  { return _cap->get_stream_info_for_id(id, &_sinfo); }

  L4::Cap<L4Re::Event> _cap;
  L4Re::Event_stream_info _sinfo;
  bool dirty;
};

template<typename DEV>
void
Virtio_input_event<DEV>::init_demux(L4::Cap<L4Re::Event> cap,
                                    Device_lookup *devs,
                                    cxx::Ref_ptr<Event_consumer> consumer,
                                    fdt32_t const *id_prop)
{
  auto &demux = Event_demux::init(cap, *devs->vmm()->registry(), consumer);

  /*
   * virtio devices are currently not hotpluggable, which means that all
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
      while ((ret = init_stream_id(id)) == -L4_EINVAL)
        demux.wait_and_discard();
    }
  else
    {
      // Use next index number
      while ((ret = init_idx(demux.num_consumers() - 1)) == -L4_EINVAL)
        demux.wait_and_discard();
    }

  L4Re::chksys(ret, "Initialize event stream info");
}

template<typename DEV>
void
Virtio_input_event<DEV>::consume(L4Re::Event_buffer::Event &e)
{
  if (e.payload.stream_id != _sinfo.stream_id || !dev()->queue_ready())
    return;

  l4virtio_input_event_t event{e.payload.type, e.payload.code,
                               static_cast<l4_uint32_t>(e.payload.value)};
  dev()->inject_event(event);
  dirty = true;
}

template<typename DEV>
void
Virtio_input_event<DEV>::notify()
{
  if (!dirty)
    return;

  dev()->notify_events();
  dirty = false;
}

template<typename DEV>
void
Virtio_input_event<DEV>::virtio_input_cfg_written(l4virtio_input_config_t *dev_cfg)
{
  switch (dev_cfg->select)
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

  // Flush the complete structure instead of selectively flushing the actually
  // used area.
  dev()->writeback_cache(dev_cfg);
}

} // namespace Vdev
