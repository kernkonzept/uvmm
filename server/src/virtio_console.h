/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "mmio_device.h"
#include "debug.h"
#include "irq.h"
#include "vcon_device.h"
#include "virtio_dev.h"
#include "virtio_event_connector.h"

#include <l4/sys/cxx/ipc_epiface>
#include <l4/cxx/type_traits>

#include <l4/sys/vcon>

#include <l4/re/error_helper>

namespace Vdev {

/**
 * Virtio device that lets guests communicate with an L4::Vcon object.
 *
 * Example device tree entry to make it available to guests:
 *   virtio_uart@20000 {
 *     compatible = "virtio,mmio";
 *     reg = <0x20000 0x100>;
 *     interrupt-parent = <0x1>;
 *     interrupts = <0x0 0x7a 0x4>;
 *     l4vmm,vdev = "console";
 *     l4vmm,vcon_cap = "guest_log";
 *   };
 *
 * "l4vmm,vcon_cap" is a capability to a L4::Vcon passed to uvmm. If it is not
 * given in the device tree or no such capability exists in uvmm's initial
 * namespace, the log of L4Re::Env is used.
 */
template <typename DEV>
class Virtio_console
: public Virtio::Dev,
  public Vcon_device,
  public L4::Irqep_t<Virtio_console<DEV> >
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
    Console_queue_num = 2,
    Console_queue_length = 0x100,
  };

  Virtio::Virtqueue _vqs[Console_queue_num];

public:
  struct Features : Virtio::Dev::Features
  {
    CXX_BITFIELD_MEMBER(0, 0, console_size, raw);
    CXX_BITFIELD_MEMBER(1, 1, console_multiport, raw);

    explicit Features(l4_uint32_t v)
    : Virtio::Dev::Features(v)
    {}
  };

  Virtio_console(Vmm::Vm_ram *ram, L4::Cap<L4::Vcon> con)
  : Virtio::Dev(ram, 0x44, L4VIRTIO_ID_CONSOLE),
    Vcon_device(con)
  {
    Features feat(0);
    feat.ring_indirect_desc() = true;
    _cfg_header->dev_features_map[0] = feat.raw;
    _cfg_header->num_queues = Console_queue_num;

    for (auto &q : _vqs)
      q.config.num_max = Console_queue_length;

    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        Dbg(Dbg::Dev, Dbg::Warn, "cons")
          .printf("WARNING: Cannot set console attributes. "
                  "Output may not work as expected.\n");
        return;
      }

    attr.set_raw();
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
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

        attach_con_irq("VirtIO console");
      }
  }

  int init_irqs(Vdev::Device_lookup *devs, Vdev::Dt_node const &self)
  { return dev()->event_connector()->init_irqs(devs, self); }

  void reset() override
  {
    for (auto &q : _vqs)
      {
        q.disable();
        q.config.ready = 0;
      }
  }

  void virtio_queue_notify(unsigned)
  {
    Virtio::Event_set ev;

    handle_input(&ev);
    int const q_idx = 1;
    auto *q = &_vqs[q_idx];

    while (q->ready())
      {
        auto r = q->next_avail();

        if (!r)
          break;

        Request_processor rp;
        Payload p;
        rp.start(this, r, &p);
        while (p.len)
          {
            long rsz = _con->write(p.data, p.len);
            if (rsz < 0)
              break;
            p.data += rsz;
            p.len  -= rsz;
          }

        q->consumed(r);
        if (!q->no_notify_guest())
          {
            _irq_status_shadow |= 1;
            ev.set(q->config.driver_notify_index);
          }
      }

    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->send_events(cxx::move(ev));
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


  void handle_input(Virtio::Event_set *ev)
  {
    int const q_idx = 0;
    auto *q = &_vqs[q_idx];

    while (1)
      {
        int r = _con->read(NULL, 0);

        if (r <= 0)
          break; // empty

        if (!q->ready())
          {
            // drop input
            do
              {
                r = _con->read(NULL, L4_VCON_READ_SIZE);
              }
            while (r > L4_VCON_READ_SIZE);
            break;
          }

        auto req = q->next_avail();

        if (!req)
          break;

        Request_processor rp;
        Payload p;
        rp.start(this, req, &p);

        if (!p.writable)
          {
            Err().printf("Virtio_console: error read-only buffer in input queue\n");
            break;
          }

        r = _con->read(p.data, p.len);
        if (r < 0)
          {
            Err().printf("Virtio_console: read error: %d\n", r);
            break;
          }

        unsigned size = static_cast<unsigned>(r) <= p.len
                        ? static_cast<unsigned>(r) : p.len;
        q->consumed(req, size);

        if (!q->no_notify_guest())
          {
            dev()->_irq_status_shadow |= 1;
            ev->set(q->config.driver_notify_index);
          }

        if (static_cast<unsigned>(r) <= p.len)
          break;
      }
  }

  void handle_irq()
  {
    Virtio::Event_set ev;
    handle_input(&ev);

    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->send_events(cxx::move(ev));
  }

  void virtio_irq_ack(unsigned val)
  {
    _irq_status_shadow &= ~val;
    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->clear_events(val);
  }

  Virtio::Virtqueue *virtqueue(unsigned qn) override
  {
    if (qn >= Console_queue_num)
      return nullptr;

    return &_vqs[qn];
  }
private:
  DEV *dev() { return static_cast<DEV *>(this); }
};

class Virtio_console_mmio
: public Virtio_console<Virtio_console_mmio>,
  public Vmm::Ro_ds_mapper_t<Virtio_console_mmio>,
  public Virtio::Mmio_connector<Virtio_console_mmio>
{
public:
  Virtio_console_mmio(Vmm::Vm_ram *ram, L4::Cap<L4::Vcon> con)
  : Virtio_console(ram, con)
  {}

  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

  char const *dev_name() const override { return "Virtio_console_mmio"; }

private:
  Virtio::Event_connector_irq _evcon;
};

}
