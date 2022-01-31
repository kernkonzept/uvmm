/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
/*
 * Copyright (C) 2015-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/error_helper>
#include <l4/re/event_enums.h>
#include <l4/l4virtio/virtio_input.h>

#include "debug.h"
#include "virtio_dev.h"
#include "virtio_event_connector.h"

namespace Vdev {

template <typename DEV>
class Virtio_input
: public Virtio::Dev
{
  typedef L4virtio::Svr::Virtqueue::Desc Desc;
  typedef L4virtio::Svr::Request_processor Request_processor;

  struct Payload
  {
    char *data;
    unsigned len;
    bool writable;
  };

  enum
  {
    Input_event_queue = 0,
    Input_status_queue = 1,
    Input_queue_num = 2,
    Input_queue_length = 0x100,
  };

protected:
  Virtio::Virtqueue _vqs[Input_queue_num];

public:
  Virtio_input(Vmm::Vm_ram *ram)
  : Virtio::Dev(ram, 0x44, L4VIRTIO_ID_INPUT)
  {
    Features feat(0);
    feat.ring_indirect_desc() = true;
    _cfg_header->dev_features_map[0] = feat.raw;
    _cfg_header->num_queues = Input_queue_num;

    for (auto &q : _vqs)
      q.config.num_max = Input_queue_length;
  }

  void virtio_queue_ready(unsigned ready)
  {
    auto *q = current_virtqueue();
    if (!q)
      return;

    auto *qc = &q->config;

    if (ready == 0 && q->ready())
      {
        q->disable();
        qc->ready = 0;
      }
    else if (ready == 1 && !q->ready())
      {
        qc->ready = 0;
        l4_uint16_t num = qc->num;
        // num must be: a power of two in range [1,num_max].
        if (!num || (num & (num - 1)) || num > qc->num_max)
          return;

        q->init_queue(dev()->template devaddr_to_virt<void>(qc->desc_addr),
                      dev()->template devaddr_to_virt<void>(qc->avail_addr),
                      dev()->template devaddr_to_virt<void>(qc->used_addr));
        qc->ready = 1;
      }
  }

  void reset() override
  {
    for (auto &q : _vqs)
      {
        q.disable();
        q.config.ready = 0;
        q.config.num_max = Input_queue_length;
      }
  }

  void load_desc(Desc const &desc, Request_processor const *, Payload *p)
  {
    p->data = devaddr_to_virt<char>(desc.addr.get(), desc.len);
    p->len = desc.len;
    p->writable = desc.flags.write();
  }

  void load_desc(Desc const &desc, Request_processor const *,
                 Desc const **table)
  {
    *table = devaddr_to_virt<Desc const>(desc.addr.get(), sizeof(Desc));
  }

  void virtio_irq_ack(unsigned val)
  {
    _irq_status_shadow &= ~val;
    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->clear_events(val);
  }

  Virtio::Virtqueue *virtqueue(unsigned qn) override
  { return qn < Input_queue_num ? &_vqs[qn] : nullptr; }

  bool inject_event(l4virtio_input_event_t &event)
  {
    auto *q = &_vqs[0];
    if (!q->ready())
      {
        Err().printf("Virtio_input: not ready yet\n");
        return false;
      }

    auto req = q->next_avail();

    if (!req)
      {
        Dbg(Dbg::Dev, Dbg::Warn, "virtio")
          .printf("Virtio_input: No request available\n");
        return false;
      }

    Request_processor rp;
    Payload p;

    rp.start(this, req, &p);

    // Check consistency of buffer
    if (!p.writable || p.len < sizeof(event))
      {
        Dbg(Dbg::Dev, Dbg::Warn, "virtio")
          .printf("Virtio_input: buffer %s\n",
                  p.writable ? "read only" : "too small");
        // return it to the queue with 0 content
        q->consumed(req, 0);
        return false;
      }

    memcpy(p.data, &event, sizeof(event));
    q->consumed(req, sizeof(event));
    return true;
  }

  int inject_events(l4virtio_input_event_t *events, size_t num)
  {
    if (!num)
      return 0;

    unsigned injected;

    auto *q = &_vqs[0];
    if (!q->ready())
      {
        Err().printf("Virtio_input: not ready yet\n");
        return 0;
      }

    for (injected = 0; injected < num; ++injected)
      {
        if (!inject_event(events[injected]))
          break;
      }

    notify_events();
    return injected;
  }

  void notify_events()
  {
    auto *q = &_vqs[0];

    // If we end up here we either successfully injected events or got an error
    // while doing so (e.g. no buffer available anymore). We notify the guest if
    // it did not disable notifications.
    // We could consider sending notifications in error cases even with disabled
    // notificatins (by adding  || (injected != num))but are currently not doing
    // so.
    if (!q->no_notify_guest())
      {
        dev()->_irq_status_shadow |= 1;
        if (_cfg_header->irq_status != _irq_status_shadow)
          dev()->set_irq_status(_irq_status_shadow);

        Virtio::Event_set ev;
        ev.set(q->config.driver_notify_index);
        dev()->event_connector()->send_events(cxx::move(ev));
      }
  }

private:
  DEV *dev() { return static_cast<DEV *>(this); }
};

}
