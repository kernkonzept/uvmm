/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/cache.h>
#include <l4/re/dataspace>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>

#include <l4/l4virtio/virtio.h>
#include <l4/l4virtio/server/virtio>

#include "device.h"
#include "mem_access.h"
#include "vm_ram.h"
#include "virtio_qword.h"

namespace Virtio {

class Virtqueue : public L4virtio::Svr::Virtqueue
{
public:
  typedef l4virtio_config_queue_t Queue_config;

  Queue_config config;

  Virtqueue()
  { memset(&config, 0, sizeof(config)); }

  void init_queue(void *desc, void *avail, void *used)
  { setup(config.num, desc, avail, used); }

};

struct Event_set
{
  l4_uint64_t e = 0;
  void reset() { e = 0; };
  void set(l4_uint16_t index)
  {
    if (index < sizeof(e) * 8)
      e |= 1ULL << index;
  }
};

/**
 * Abstract interface for virtio event handling.
 *
 * \note This interface is currently just for the sake of documentation.
 */
class Event_if
{
public:
  /**
   * Inject the given set of events into the VM.
   *
   * \param ev  Set of pending events to be injected into the guest.
   */
  virtual void send_events(Event_set &&ev) = 0;

  /**
   * Acknowledge via the virtio irq_ack register.
   *
   * \param mask  The value written to the virtio irq_ack register.
   */
  virtual void clear_events(unsigned mask) = 0;
};

class Dev : public Vdev::Device
{
public:
  typedef L4virtio::Svr::Dev_status Status;
  typedef L4virtio::Svr::Dev_features Features;
  typedef l4virtio_config_queue_t Queue_config;

protected:
  enum { Config_ds_size = L4_PAGESIZE };
  l4_uint32_t _irq_status_shadow = 0;
  l4_uint16_t _config_event_index = 0;

  L4Re::Rm::Unique_region<l4virtio_config_hdr_t *> _cfg_header;
  L4Re::Util::Unique_del_cap<L4Re::Dataspace> _cfg_ds;

  void update_virtio_config()
  {
    l4_cache_clean_data((l4_addr_t)_cfg_header.get(),
                        (l4_addr_t)_cfg_header.get() + Config_ds_size - 1);
  }

public:
  Dev(Vmm::Vm_ram *iommu, l4_uint32_t vendor, l4_uint32_t device)
  : _iommu(iommu)
  {
    auto *e = L4Re::Env::env();
    auto ds = L4Re::chkcap(L4Re::Util::make_unique_del_cap<L4Re::Dataspace>());

    L4Re::chksys(e->mem_alloc()->alloc(Config_ds_size, ds.get()));

    L4Re::Rm::Unique_region<l4virtio_config_hdr_t *> cfg;
    L4Re::chksys(e->rm()->attach(&cfg, Config_ds_size,
                                 L4Re::Rm::Search_addr
                                 , //| L4Re::Rm::Cache_uncached,
                                 L4::Ipc::make_cap_rw(ds.get())));

    _cfg_ds = cxx::move(ds);
    _cfg_header = cxx::move(cfg);

    _cfg_header->magic = 0x74726976; // virt
    _cfg_header->version = 2;
    _cfg_header->device = device;
    _cfg_header->vendor = vendor;
    _cfg_header->dev_features_map[1] = 1; // set VERSION 1 flag

    update_virtio_config();
  }

  virtual Virtqueue *virtqueue(unsigned qn) = 0;

  Virtqueue *current_virtqueue()
  {
    return virtqueue(_cfg_header->queue_sel);
  }

  Queue_config *current_virtqueue_config()
  {
    auto *q = current_virtqueue();
    return q ? &q->config : nullptr;
  }

  l4virtio_config_hdr_t *mmio_local_addr() const
  { return _cfg_header.get(); }

  l4_size_t mapped_mmio_size() const
  { return Config_ds_size; }

  L4::Cap<L4Re::Dataspace> mmio_ds() const
  { return _cfg_ds.get(); }

  l4virtio_config_hdr_t *virtio_cfg()
  { return _cfg_header.get(); }

  void virtio_device_config_written(unsigned /*reg*/) {}
  virtual void reset() {}

  void virtio_set_status(l4_uint32_t status)
  {
    _cfg_header->status = status;
    if (status == 0)
      reset();
  }

  template<typename T>
  T *devaddr_to_virt(l4_addr_t devaddr, l4_size_t len = 0) const
  {
    if (devaddr < _iommu->vm_start()
        || devaddr - _iommu->vm_start() + len > _iommu->size())
      L4Re::chksys(-L4_ERANGE, "Virtio pointer outside RAM region");

    return _iommu->access(L4virtio::Ptr<T>(devaddr));
  }

private:
  Vmm::Vm_ram *_iommu;
};


template<typename DEV>
class Mmio_connector
{
private:
  template<typename T>
  void writeback_cache(T const *p)
  {
    l4_cache_clean_data((l4_addr_t)p, (l4_addr_t)p + sizeof(T) - 1);
  }

public:
  void set_irq_status(l4_uint32_t irq_status)
  {
    auto *vcfg = dev()->virtio_cfg();
    vcfg->irq_status = irq_status;
    writeback_cache(&vcfg->irq_status);
  }

  void write(unsigned reg, char size, l4_uint64_t value, unsigned)
  {
    auto *vcfg = dev()->virtio_cfg();
    if (L4_UNLIKELY(reg >= dev()->mapped_mmio_size()))
      return;

    if (L4_UNLIKELY((reg + (1U << size)) > dev()->mapped_mmio_size()))
      return;

    if (L4_UNLIKELY(reg & ((1U << size) - 1)))
      return;
    if (reg >= 0x100)
      {
        l4_addr_t a = (l4_addr_t)vcfg + reg;
        if (Vmm::Mem_access::write_width(a, value, size) == L4_EOK)
          dev()->virtio_device_config_written(reg);
        return;
      }

    if (size < 2)
      return;

    switch (reg)
      {
      case 0x14:
        vcfg->dev_features_sel = value;
        if (value < (sizeof(vcfg->dev_features_map) / 4))
          vcfg->dev_features = vcfg->dev_features_map[value];
        else
          vcfg->dev_features = 0;
        writeback_cache(&vcfg->dev_features);
        break;

      case 0x20:
          {
            unsigned sel = cxx::access_once(&vcfg->driver_features_sel);
            vcfg->driver_features = value;
            if (sel < (sizeof(vcfg->driver_features_map) / 4))
              vcfg->driver_features_map[sel] = value;
          }
        break;

      case 0x24:
        vcfg->driver_features_sel = value;
        break;

      case 0x30:
        {
          vcfg->queue_sel = value;
          auto *qc = dev()->current_virtqueue_config();
          if (!qc)
            {
              vcfg->queue_num_max = 0;
              vcfg->queue_ready = 0;
              break;
            }

          vcfg->queue_num_max = qc->num_max;
          vcfg->queue_ready = qc->ready;
          vcfg->queue_desc = qc->desc_addr;
          vcfg->queue_avail = qc->avail_addr;
          vcfg->queue_used = qc->used_addr;
          writeback_cache(&vcfg->queue_num_max);
          writeback_cache(&vcfg->queue_ready);
          break;
        }

      case 0x38:
        {
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            qc->num = value;

          vcfg->queue_num = value;
          break;
        }

      case 0x44:
        {
          dev()->virtio_queue_ready(value);

          auto *cfg = dev()->current_virtqueue_config();
          vcfg->queue_ready = cfg ? cfg->ready : 0;

          writeback_cache(&vcfg->queue_ready);
          writeback_cache(&vcfg->queue_num_max);
          break;
        }

      case 0x50: dev()->virtio_queue_notify(value); break;

      case 0x64:
        dev()->virtio_irq_ack(value);
        writeback_cache(&vcfg->irq_status);
        break;

      case 0x70:
        dev()->virtio_set_status(value);
        writeback_cache(&vcfg->status);
        writeback_cache(&vcfg->irq_status);
        break;

      case 0x80:
      case 0x84:
        {
          int i = reg == 0x80 ? 0 : 1;
          ((Virtio::Qword *)(&vcfg->queue_desc))->w[i] = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            ((Virtio::Qword *)(&qc->desc_addr))->w[i] = value;
          break;
        }

      case 0x90:
      case 0x94:
        {
          int i = reg == 0x90 ? 0 : 1;
          ((Virtio::Qword *)(&vcfg->queue_avail))->w[i] = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            ((Virtio::Qword *)(&qc->avail_addr))->w[i] = value;
          break;
        }

      case 0xa0:
      case 0xa4:
        {
          int i = reg == 0xa0 ? 0 : 1;
          ((Virtio::Qword *)(&vcfg->queue_used))->w[i] = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            ((Virtio::Qword *)(&qc->used_addr))->w[i] = value;
          break;
        }
      }
  }

private:
  DEV *dev()
  { return static_cast<DEV *>(this); }
};

}
