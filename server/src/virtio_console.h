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
#include "virtio_dev.h"
#include "virtio_event_connector.h"

#include <l4/cxx/ipc_server>
#include <l4/cxx/ipc_stream>
#include <l4/cxx/type_traits>

#include <l4/sys/vcon>

#include <l4/re/error_helper>

namespace Vdev {

template <typename DEV>
class Virtio_console
: public Virtio::Dev,
  private L4::Server_object_t<L4::Vcon>
{
  typedef L4virtio::Svr::Virtqueue::Desc Desc;
  typedef L4virtio::Svr::Request_processor Request_processor;

  struct Payload
  {
    char *data;
    unsigned len;
    bool writable;
  };

public:
  struct Features : Virtio::Dev::Features
  {
    CXX_BITFIELD_MEMBER(0, 0, console_size, raw);
    CXX_BITFIELD_MEMBER(1, 1, console_multiport, raw);

    explicit Features(l4_uint32_t v) : Virtio::Dev::Features(v) {}
  };

  Virtio_console(Vmm::Vm_ram *iommu, L4::Cap<L4::Vcon> con)
  : Virtio::Dev(iommu, 0x44, L4VIRTIO_ID_CONSOLE), _con(con)
  {
    _q[0].config.num_max = 0x100;
    _q[1].config.num_max = 0x100;

    l4_vcon_attr_t attr;
    if (l4_error(con->get_attr(&attr)) != L4_EOK)
      {
        Dbg(Dbg::Dev, Dbg::Warn, "cons")
          .printf("WARNING: Cannot set console attributes. "
                  "Output may not work as expected.\n");
        return;
      }

    attr.l_flags &= ~L4_VCON_ECHO;
    attr.o_flags &= ~L4_VCON_ONLRET;
    L4Re::chksys(con->set_attr(&attr), "console set_attr");
  }

  void virtio_select_queue(unsigned qn)
  {
    _cfg_header->queue_sel = qn;
    if (qn >= 2)
      {
        _cfg_header->queue_num_max = 0;
        _cfg_header->queue_ready = 0;
        return;
      }

    _cfg_header->queue_num_max = _q[qn].config.num_max;
    _cfg_header->queue_ready = _q[qn].ready() ? 1 : 0;
  }

  void virtio_queue_ready(unsigned ready)
  {
    if (_cfg_header->queue_sel >= 2)
      return;

    auto *q = &_q[_cfg_header->queue_sel];
    if (ready == 0 && q->ready())
      {
        q->disable();
        _cfg_header->queue_ready = 0;
      }
    else if (ready == 1 && !q->ready())
      {
        _cfg_header->queue_ready = 0;
        if (_cfg_header->queue_num > q->config.num_max)
          return;

        q->config.num = _cfg_header->queue_num;
        q->init_queue(dev()->template devaddr_to_virt<void>(_cfg_header->queue_desc),
                      dev()->template devaddr_to_virt<void>(_cfg_header->queue_avail),
                      dev()->template devaddr_to_virt<void>(_cfg_header->queue_used));

        _cfg_header->queue_ready = 1;
      }
  }

  void init_device(Vdev::Device_lookup const *devs,
                   Vdev::Dt_node const &self,
                   Vmm::Guest *, Vmm::Virt_bus *) override
  {
    int err = dev()->event_connector()->init_irqs(devs, self);
    if (err < 0)
      Dbg(Dbg::Dev, Dbg::Warn, "virtio")
        .printf("Cannot connect virtio IRQ: %d\n", err);
  }

  void reset()
  {
    _q[0].disable();
    _q[1].disable();
  }

  void virtio_queue_notify(unsigned)
  {
    Virtio::Event_set ev;

    handle_input(&ev);
    int const q_idx = 1;
    auto *q = &_q[q_idx];

    auto r = q->next_avail();
    if (r)
      {
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
        _irq_status_shadow |= 1;
        ev.set(q->event_index);
      }

    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->send_events(cxx::move(ev));
  }

  l4_uint32_t host_feature(unsigned id)
  {
    switch (id)
      {
      case 0:
        {
          Features feat(0);
          feat.ring_indirect_desc() = true;
          return feat.raw;
        }
      default:
        return 0;
      }
  }

  void load_desc(Desc const &desc, Request_processor const *, Payload *p)
  {
    // XXX boundary check?
    p->data = (char *)_iommu->access(desc.addr);
    p->len = desc.len;
    p->writable = desc.flags.write();
  }

  void load_desc(Desc const &desc, Request_processor const *,
                 Desc const **table)
  {
    // XXX boundary check?
    *table = static_cast<Desc const *>(_iommu->access(desc.addr));
  }


  void handle_input(Virtio::Event_set *ev)
  {
    int const q_idx = 0;
    auto *q = &_q[q_idx];

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

        if ((unsigned)r <= p.len)
          {
            q->consumed(req, r);
            dev()->_irq_status_shadow |= 1;
            ev->set(q->event_index);
            break;
          }

        q->consumed(req, p.len);
        dev()->_irq_status_shadow |= 1;
        ev->set(q->event_index);
      }
  }

  template<typename REG>
  void register_obj(REG *registry)
  {
    _con->bind(0, L4Re::chkcap(registry->register_irq_obj(this)));
  }

  int dispatch(l4_umword_t /*obj*/, L4::Ipc::Iostream &/*ios*/)
  {
    Virtio::Event_set ev;
    handle_input(&ev);

    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->send_events(cxx::move(ev));
    return 0;
  }

  void virtio_irq_ack(unsigned val)
  {
    _irq_status_shadow &= ~val;
    if (_cfg_header->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->clear_events(val);
  }

private:
  Virtio::Virtqueue _q[2];
  L4::Cap<L4::Vcon> _con;

  DEV *dev() { return static_cast<DEV *>(this); }
};

class Virtio_console_mmio
: public Virtio_console<Virtio_console_mmio>,
  public Vmm::Ro_ds_mapper_t<Virtio_console_mmio>,
  public Virtio::Mmio_connector<Virtio_console_mmio>
{
public:
  Virtio_console_mmio(Vmm::Vm_ram *iommu,
                      L4::Cap<L4::Vcon> con = L4Re::Env::env()->log())
  : Virtio_console(iommu, con)
  {}

  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

private:
  Virtio::Event_connector_irq _evcon;
};

}
