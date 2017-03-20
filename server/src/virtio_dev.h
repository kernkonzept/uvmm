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

#include <l4/l4virtio/virtio.h>
#include <l4/l4virtio/server/virtio>

#include "device.h"
#include "vm_ram.h"

namespace Virtio {

class Virtqueue : public L4virtio::Svr::Virtqueue
{
public:
  typedef l4virtio_config_queue_t Queue_config;

  Queue_config config;
  l4_uint16_t event_index = 0;

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

protected:
  enum { Config_ds_size = L4_PAGESIZE };
  l4_uint32_t _irq_status_shadow = 0;
  l4_uint16_t _config_event_index = 0;

  Vmm::Vm_ram *_iommu;

  L4Re::Rm::Auto_region<l4virtio_config_hdr_t *> _cfg_header;
  L4Re::Util::Auto_del_cap<L4Re::Dataspace>::Cap _cfg_ds;

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
    auto ds = L4Re::chkcap(L4Re::Util::make_auto_del_cap<L4Re::Dataspace>());

    L4Re::chksys(e->mem_alloc()->alloc(Config_ds_size, ds.get()));

    L4Re::Rm::Auto_region<l4virtio_config_hdr_t *> cfg;
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
  T *devaddr_to_virt(l4_addr_t devaddr) const
  { return _iommu->access(L4virtio::Ptr<T>(devaddr)); }
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
        switch (size)
          {
          case Vmm::Mem_access::Wd8:  *reinterpret_cast<l4_uint8_t *>(a) = value;  break;
          case Vmm::Mem_access::Wd16: *reinterpret_cast<l4_uint16_t *>(a) = value; break;
          case Vmm::Mem_access::Wd32: *reinterpret_cast<l4_uint32_t *>(a) = value; break;
          case Vmm::Mem_access::Wd64: *reinterpret_cast<l4_uint64_t *>(a) = value; break;
          default: return;
          }
        dev()->virtio_device_config_written(reg);
        return;
      }

    union Qword
    {
      l4_uint32_t w[2];
      l4_uint64_t q;
    };

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
        dev()->virtio_select_queue(value);
        writeback_cache(&vcfg->queue_num_max);
        writeback_cache(&vcfg->queue_ready);
        break;

      case 0x38:
        vcfg->queue_num = value;
        break;

      case 0x44:
        dev()->virtio_queue_ready(value);
        writeback_cache(&vcfg->queue_num_max);
        writeback_cache(&vcfg->queue_ready);
        break;

      case 0x50:
        dev()->virtio_queue_notify(value);
        break;

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
        ((Qword *)(&vcfg->queue_desc))->w[0] = value;
        break;

      case 0x84:
        ((Qword *)(&vcfg->queue_desc))->w[1] = value;
        break;

      case 0x90:
        ((Qword *)(&vcfg->queue_avail))->w[0] = value;
        break;

      case 0x94:
        ((Qword *)(&vcfg->queue_avail))->w[1] = value;
        break;

      case 0xa0:
        ((Qword *)(&vcfg->queue_used))->w[0] = value;
        break;

      case 0xa4:
        ((Qword *)(&vcfg->queue_used))->w[1] = value;
        break;
      }
  }

private:
  DEV *dev()
  { return static_cast<DEV *>(this); }
};

}
