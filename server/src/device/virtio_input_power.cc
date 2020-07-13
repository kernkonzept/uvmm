/*
 * Copyright (C) 2015-2018 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cstring>

#include "virtio_input.h"
#include "mmio_device.h"
#include "irq.h"
#include "device_factory.h"
#include "guest.h"
#include "monitor/virtio_input_power_cmd_handler.h"

#include <l4/sys/cxx/ipc_epiface>
#include <l4/cxx/type_traits>

#include <l4/sys/vcon>


#include <l4/re/event_enums.h>
#include <l4/re/env>

namespace Vdev {

l4_uint16_t translate_char(unsigned char c);

class Virtio_input_power_mmio
: public Virtio_input<Virtio_input_power_mmio>,
  public Vmm::Ro_ds_mapper_t<Virtio_input_power_mmio>,
  public Virtio::Mmio_connector<Virtio_input_power_mmio>,
  public L4::Irqep_t<Virtio_input_power_mmio>,
  public Monitor::Virtio_input_power_cmd_handler<Monitor::Enabled,
                                                 Virtio_input_power_mmio>
{
  friend Virtio_input_power_cmd_handler<Monitor::Enabled,
                                        Virtio_input_power_mmio>;

public:
  Virtio_input_power_mmio(Vmm::Vm_ram *ram, L4::Cap<L4::Vcon> con)
  : Virtio_input(ram), _con(con)
  {}

  int init_irqs(Vdev::Device_lookup *devs, Vdev::Dt_node const &self)
  { return event_connector()->init_irqs(devs, self); }


  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

  void register_obj(L4::Registry_iface *registry)
  {
    _con->bind(0, L4Re::chkcap(registry->register_irq_obj(this)));
  }

  void handle_irq();

  void virtio_queue_notify(unsigned val)
  {
    // We do not handle the status queue and we do not keep pending events. So
    // we do not need to do anything if queue 0 is notified (signalling the
    // addition of buffers to the queue). We could disable notifications here
    // but are not doing it at the moment.
    if (val)
      Dbg(Dbg::Dev, Dbg::Info).printf("Pending request in queue %d\n", val);
  }

  int inject_events(Virtio_input_event *events, size_t num)
  { return Virtio_input<Virtio_input_power_mmio>::inject_events(events, num); }

  bool inject_command(unsigned char c);

  void virtio_device_config_written(unsigned reg);

private:
  void virtio_input_cfg_written(l4virtio_input_config_t *dev_cfg);
  void set_bit(l4virtio_input_config_t *dev_cfg, unsigned bit)
  {
    size_t elem_size = sizeof(dev_cfg->u.bitmap[0]) * 8;
    dev_cfg->u.bitmap[bit / elem_size] |= (1 << bit % elem_size);
  }

  void inject_events(Virtio_input_event *events, size_t num, char const *msg)
  {
    int res = inject_events(events, num);
    if (res != static_cast<int>(num))
      Dbg(Dbg::Dev, Dbg::Warn, "virtio")
        .printf("Virtio_input:%s Injected only %d/%zd events\n", msg, res, num);
  }

  void inject_apm_suspend();
  void inject_event(l4_uint16_t event, const char*);

  Virtio::Event_connector_irq _evcon;
  L4::Cap<L4::Vcon> _con;
};

void
Virtio_input_power_mmio::virtio_input_cfg_written(l4virtio_input_config_t *dev_cfg)
{
  switch(dev_cfg->select)
  {
    case L4VIRTIO_INPUT_CFG_ID_NAME:
      {
        char const *name = "Uvmm-power-notification";
        strncpy(dev_cfg->u.string, name, sizeof(dev_cfg->u.string));
        dev_cfg->size = std::min(strlen(name) + 1, sizeof(dev_cfg->u.string));
      }
      break;
    case L4VIRTIO_INPUT_CFG_ID_SERIAL:
      {
        char const *id = "0815";
        strncpy(dev_cfg->u.string, id, sizeof(dev_cfg->u.string));
        dev_cfg->size = std::min(strlen(id) + 1, sizeof(dev_cfg->u.string));
      }
      break;
    case L4VIRTIO_INPUT_CFG_ID_DEVIDS:
      dev_cfg->u.ids = { 1, 1, 1, 1 };
      dev_cfg->size = sizeof(l4virtio_input_devids_t);
      break;
    case L4VIRTIO_INPUT_CFG_EV_BITS:
      memset(dev_cfg->u.bitmap, 0, sizeof(dev_cfg->u.bitmap));
      dev_cfg->size = 0;
      if (dev_cfg->subsel == L4RE_EV_KEY)
        {
          // We are able to generate key events for [A-Za-z0-9 ] and a selected
          // set of power related events even though the Virtio_input_power
          // device only generate power related events.
          //
          // Other events like leftalt or sysrq are needed to support the
          // injection of alt sysrq events to the guest.
          for (char c = '0'; c <= '9'; ++c)
            set_bit(dev_cfg, translate_char(c));
          for (char c = 'A'; c <= 'Z'; ++c)
            set_bit(dev_cfg, translate_char(c));
          for (char c = 'a'; c <= 'z'; ++c)
            set_bit(dev_cfg, translate_char(c));

          l4_uint16_t events[] = {
              L4RE_KEY_POWER,
              L4RE_KEY_POWER2,
              L4RE_KEY_SLEEP,
              L4RE_KEY_SUSPEND,
              L4RE_KEY_LEFTALT,
              L4RE_KEY_SYSRQ,
              L4RE_KEY_SPACE,
          };
          for (auto ev : events)
            set_bit(dev_cfg, ev);

          dev_cfg->size = sizeof(dev_cfg->u.bitmap);
        }
      else if (dev_cfg->subsel == L4RE_EV_PWR)
        {
          // Current Linux versions do not query events for EV_PWR.
          // Here we guard against changes in this regard and generate an error
          // message.
          Dbg(Dbg::Dev, Dbg::Warn, "virtio")
            .printf("Virtio_input: Guest queries EV_PWR events "
                    "- not handled yet.\n");
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
Virtio_input_power_mmio::virtio_device_config_written(unsigned reg)
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

void
Virtio_input_power_mmio::handle_irq()
{
  int const q_idx = 0;
  auto *q = &_vqs[q_idx];

  while (1)
    {
      int r = _con->read(NULL, 0);

      if (r <= 0)
        break; // empty

      char cmd;
      r = _con->read(&cmd, sizeof(cmd));
      if (r < 0)
        {
          Err().printf("Virtio_console: read error: %d\n", r);
          break;
        }

      if (!q->ready())
        {
          char response[] = "NotReady\n";
          _con->write(response, sizeof(response) - 1);
          break;
        }

      if (!q->desc_avail())
        {
          char response[] = "NoMem\n";
          _con->write(response, sizeof(response) - 1);
          break;
        }

      switch(cmd)
      {
        case 'a': inject_apm_suspend(); break;
        case 's': inject_event(L4RE_KEY_SUSPEND, "inject suspend"); break;
        case 'l': inject_event(L4RE_KEY_SLEEP, "inject sleep"); break;
        case 'p': inject_event(L4RE_KEY_POWER, "inject power"); break;
        case 'q': inject_event(L4RE_KEY_POWER2, "inject power2"); break;
        case 'h':
          {
            char response[] = "a: apm suspend\ns: suspend\nl: sleep\np: power\n"
                              "q: power2\n";
            _con->write(response, sizeof(response) - 1);
          }
          break;
        default:
          Dbg(Dbg::Dev, Dbg::Warn, "pwr-input")
            .printf("Unknown character '%c'\n", cmd);
          break;
      }
      _con->write("OK\n", 3);
    }
}
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

void
Virtio_input_power_mmio::inject_apm_suspend()
{
  Virtio_input_event events[] = {
      {L4RE_EV_PWR, L4RE_KEY_SUSPEND, 1},
      {L4RE_EV_SYN, L4RE_SYN_REPORT, 1},
      {L4RE_EV_PWR, L4RE_KEY_SUSPEND, 0},
      {L4RE_EV_SYN, L4RE_SYN_REPORT, 1}
  };
  inject_events(events, ARRAY_SIZE(events), __func__);
}

void
Virtio_input_power_mmio::inject_event(l4_uint16_t event, char const * msg)
{
  Virtio_input_event events[] = {
      {L4RE_EV_KEY, event, 1},
      {L4RE_EV_SYN, L4RE_SYN_REPORT, 1},
      {L4RE_EV_KEY, event, 0},
      {L4RE_EV_SYN, L4RE_SYN_REPORT, 1}
  };
  inject_events(events, ARRAY_SIZE(events), msg);
}

bool
Virtio_input_power_mmio::inject_command(unsigned char c)
{
  auto event = Vdev::translate_char(c);
  Vdev::Virtio_input_event events[] = {
      {L4RE_EV_KEY, L4RE_KEY_LEFTALT, 1},
      {L4RE_EV_KEY, L4RE_KEY_SYSRQ, 1},
      {L4RE_EV_KEY, event, 1},
      {L4RE_EV_SYN, L4RE_SYN_REPORT, 1},
      {L4RE_EV_KEY, event, 0},
      {L4RE_EV_KEY, L4RE_KEY_SYSRQ, 0},
      {L4RE_EV_KEY, L4RE_KEY_LEFTALT, 0},
      {L4RE_EV_SYN, L4RE_SYN_REPORT, 1}
  };

  auto num = (int)ARRAY_SIZE(events);
  return inject_events(events, num) == num;
}

//
// Helper functions for monitor interface
//
static L4Re_events_key transtab[] = {
    L4RE_KEY_0,
    L4RE_KEY_1,
    L4RE_KEY_2,
    L4RE_KEY_3,
    L4RE_KEY_4,
    L4RE_KEY_5,
    L4RE_KEY_6,
    L4RE_KEY_7,
    L4RE_KEY_8,
    L4RE_KEY_9,
    L4RE_KEY_A,
    L4RE_KEY_B,
    L4RE_KEY_C,
    L4RE_KEY_D,
    L4RE_KEY_E,
    L4RE_KEY_F,
    L4RE_KEY_G,
    L4RE_KEY_H,
    L4RE_KEY_I,
    L4RE_KEY_J,
    L4RE_KEY_K,
    L4RE_KEY_L,
    L4RE_KEY_M,
    L4RE_KEY_N,
    L4RE_KEY_O,
    L4RE_KEY_P,
    L4RE_KEY_Q,
    L4RE_KEY_R,
    L4RE_KEY_S,
    L4RE_KEY_T,
    L4RE_KEY_U,
    L4RE_KEY_V,
    L4RE_KEY_W,
    L4RE_KEY_X,
    L4RE_KEY_Y,
    L4RE_KEY_Z
};

l4_uint16_t
translate_char(unsigned char c)
{
  l4_uint16_t res;

  if ('0' <= c && c <= '9')
    res = transtab[c - '0'];
  else if ('A' <= c && c <= 'Z')
    res = transtab[c + 10U - 'A' ];
  else if ('a' <= c && c <= 'z')
    res = transtab[c + 10U - 'a'];
  else
    // map everything to space as default
    res = L4RE_KEY_SPACE;

  return res;
}
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Device_lookup *devs, Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create virtual input device\n");
    bool monitor = node.has_prop("l4vmm,monitor");

    auto cap = Vdev::get_cap<L4::Vcon>(node, "l4vmm,virtiocap");
    if (!cap && !monitor)
      return nullptr;

    auto c = make_device<Virtio_input_power_mmio>(devs->ram().get(), cap);
    if (c->init_irqs(devs, node) < 0)
      return nullptr;

    if (cap)
      c->register_obj(devs->vmm()->registry());

    devs->vmm()->register_mmio_device(c, Vmm::Region_type::Virtual, node);

    return c;
  }
};

static F f;
static Device_type t = { "virtio,mmio", "input-power", &f };

}
