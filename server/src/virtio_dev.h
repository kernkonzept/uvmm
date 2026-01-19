/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
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

#include "virtio.h"
#include "device.h"
#include "mem_access.h"
#include "vm_ram.h"
#include "monitor/virtio_cmd_handler.h"

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

class Dev
: public Vdev::Device,
  public Monitor::Virtio_dev_cmd_handler<Monitor::Enabled, Dev>
{
public:
  typedef L4virtio::Svr::Dev_status Status;
  typedef L4virtio::Svr::Dev_features Features;
  typedef l4virtio_config_queue_t Queue_config;

protected:
  enum { Config_ds_size = L4_PAGESIZE };
  l4_uint32_t _irq_status_shadow = 0;

  L4Re::Rm::Unique_region<l4virtio_config_hdr_t *> _cfg_header;
  L4Re::Util::Unique_del_cap<L4Re::Dataspace> _cfg_ds;

public:
  Dev(Vmm::Vm_ram *ram, l4_uint32_t vendor, l4_uint32_t device)
  : _ram(ram)
  {
    auto *e = L4Re::Env::env();
    auto ds = L4Re::chkcap(L4Re::Util::make_unique_del_cap<L4Re::Dataspace>(),
                           "Allocate Virtio::Dev dataspace capability.");

    L4Re::chksys(e->mem_alloc()->alloc(Config_ds_size, ds.get()),
                 "Allocate Virtio::Dev configuration memory.");

    L4Re::Rm::Unique_region<l4virtio_config_hdr_t *> cfg;
    L4Re::chksys(e->rm()->attach(&cfg, Config_ds_size,
                                 L4Re::Rm::F::Search_addr
                                   | L4Re::Rm::F::Eager_map
                                   | L4Re::Rm::F::RW,
                                 L4::Ipc::make_cap_rw(ds.get())),
                 "Attach Virtio::Dev configuration memory in address space.");

    _cfg_ds = cxx::move(ds);
    _cfg_header = cxx::move(cfg);

    _cfg_header->magic = L4VIRTIO_MAGIC; // virt
    _cfg_header->version = 2;
    _cfg_header->device = device;
    _cfg_header->vendor = vendor;
    _cfg_header->dev_features_map[1] = 1; // set VERSION 1 flag
  }

  virtual Virtqueue *virtqueue(unsigned qn) = 0;

  Virtqueue *current_virtqueue()
  {
    return virtqueue(_cfg_header->queue_sel);
  }

  Queue_config *virtqueue_config(unsigned qn)
  {
    auto *q = virtqueue(qn);
    return q ? &q->config : nullptr;
  }

  Queue_config *current_virtqueue_config()
  {
    auto *q = current_virtqueue();
    return q ? &q->config : nullptr;
  }

  L4::Cap<L4Re::Dataspace> mmio_ds() const
  { return _cfg_ds.get(); }

  l4_size_t mmio_size() const
  { return Config_ds_size; }

  l4_addr_t local_addr() const
  { return reinterpret_cast<l4_addr_t>(_cfg_header.get()); }

  l4virtio_config_hdr_t *virtio_cfg() const
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
  { return _ram->guest2host<T *>(Vmm::Region::ss(Vmm::Guest_addr(devaddr), len, Vmm::Region_type::Ram)); }

private:
  Vmm::Vm_ram *_ram;
};

/**
 * The Mmio_connector directs the MMIO access from the guest to a specific
 * device.
 *
 * The device can be the Dev class here in this file, which is used for
 * build-in Vmm virtio devices. However, it could also be something else, where
 * the device itself comes from the outside of the Vmm (e.g. a Virtio_proxy).
 */
template<typename DEV>
class Mmio_connector
{
  enum { Device_config_start = 0x100 };

protected:
  template<typename T>
  T *virtio_device_config()
  { return reinterpret_cast<T *>(dev()->local_addr() + Device_config_start); }

public:
  void set_irq_status(l4_uint32_t irq_status)
  {
    auto *vcfg = dev()->virtio_cfg();
    vcfg->irq_status = irq_status;
  }

  l4_uint64_t read(unsigned reg, char width, unsigned /*cpu_id*/)
  {
    if (L4_UNLIKELY(reg >= dev()->mmio_size()))
      return 0;

    // only naturally aligned 32bit accesses are allowed
    if (L4_UNLIKELY(reg & ((1UL << width) - 1)))
      return 0;

    // device config can be freely read
    if (reg >= Device_config_start)
      return Vmm::Mem_access::read_width(dev()->local_addr() + reg, width);

    // only official fields are supported
    switch (reg)
      {
      case Virtio::Hdr_off_magic:
      case Virtio::Hdr_off_version:
      case Virtio::Hdr_off_device:
      case Virtio::Hdr_off_vendor:
      case Virtio::Hdr_off_dev_features:
      case Virtio::Hdr_off_dev_features_sel:
      case Virtio::Hdr_off_driver_features:
      case Virtio::Hdr_off_driver_features_sel:
      case Virtio::Hdr_off_queue_sel:
      case Virtio::Hdr_off_queue_num_max:
      case Virtio::Hdr_off_queue_num:
      case Virtio::Hdr_off_queue_ready:
      case Virtio::Hdr_off_queue_notify:
      case Virtio::Hdr_off_irq_status:
      case Virtio::Hdr_off_irq_ack:
      case Virtio::Hdr_off_status:
      case Virtio::Hdr_off_queue_desc_low:
      case Virtio::Hdr_off_queue_desc_high:
      case Virtio::Hdr_off_queue_avail_low:
      case Virtio::Hdr_off_queue_avail_high:
      case Virtio::Hdr_off_queue_used_low:
      case Virtio::Hdr_off_queue_used_high:
      case Virtio::Hdr_off_shm_len_low:
      case Virtio::Hdr_off_shm_len_high:
      case Virtio::Hdr_off_shm_base_low:
      case Virtio::Hdr_off_shm_base_high:
      case Virtio::Hdr_off_generation:
        return Vmm::Mem_access::read_width(dev()->local_addr() + reg, width);
      default:
        return 0;
      };
  }

  void write(unsigned reg, char width, l4_uint64_t value, unsigned /*cpu_id*/)
  {
    auto *vcfg = dev()->virtio_cfg();
    if (L4_UNLIKELY(reg >= dev()->mmio_size()))
      return;

    if (L4_UNLIKELY((reg + (1U << width)) > dev()->mmio_size()))
      return;

    // only naturally aligned 32bit accesses are allowed
    if (L4_UNLIKELY(reg & ((1U << width) - 1)))
      return;

    // device config can be freely written
    if (reg >= Device_config_start)
      {
        auto l = dev()->local_addr() + reg;
        if (Vmm::Mem_access::write_width(l, value, width) == L4_EOK)
          dev()->virtio_device_config_written(reg - Device_config_start);
        return;
      }

    if (width < 2)
      return;

    // not all regs can be written, we limit it to the following virtio driver
    // writeable fields:
    switch (reg)
      {
      case Virtio::Hdr_off_dev_features_sel:
        {
          vcfg->dev_features_sel = value;
          if (value < (sizeof(vcfg->dev_features_map) / 4))
            vcfg->dev_features = vcfg->dev_features_map[value];
          else
            vcfg->dev_features = 0;
          break;
        }

      case Virtio::Hdr_off_driver_features:
        {
          unsigned sel = cxx::access_once(&vcfg->driver_features_sel);
          vcfg->driver_features = value;
          if (sel < (sizeof(vcfg->driver_features_map) / 4))
            vcfg->driver_features_map[sel] = value;
          break;
        }

      case Virtio::Hdr_off_driver_features_sel:
        vcfg->driver_features_sel = value;
        break;

      case Virtio::Hdr_off_queue_sel:
        {
          vcfg->queue_sel = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            {
              // Copy the queue config from the L4virtio extension into the
              // virtio header
              vcfg->queue_num = qc->num;
              vcfg->queue_num_max = qc->num_max;
              vcfg->queue_ready = qc->ready;
              vcfg->queue_desc = qc->desc_addr;
              vcfg->queue_avail = qc->avail_addr;
              vcfg->queue_used = qc->used_addr;
            }
          else
            {
              // Reset
              vcfg->queue_num = 0;
              vcfg->queue_num_max = 0;
              vcfg->queue_ready = 0;
              vcfg->queue_desc = 0;
              vcfg->queue_avail = 0;
              vcfg->queue_used = 0;
            }
          break;
        }

      case Virtio::Hdr_off_queue_num:
        {
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            qc->num = value;

          vcfg->queue_num = value;
          break;
        }

      case Virtio::Hdr_off_queue_ready:
        {
          dev()->virtio_queue_ready(value);

          auto *cfg = dev()->current_virtqueue_config();
          vcfg->queue_ready = cfg ? cfg->ready : 0;
          break;
        }

      case Virtio::Hdr_off_queue_notify:
        vcfg->queue_notify = value;
        dev()->virtio_queue_notify(value);
        break;

      case Virtio::Hdr_off_irq_ack:
        dev()->virtio_irq_ack(value);
        break;

      case Virtio::Hdr_off_status:
        dev()->virtio_set_status(value);
        break;

      case Virtio::Hdr_off_queue_desc_low:
      case Virtio::Hdr_off_queue_desc_high:
        {
          int i = reg == Virtio::Hdr_off_queue_desc_low ? 0 : 1;
          (reinterpret_cast<Virtio::Qword *>(&vcfg->queue_desc))->w[i] = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            (reinterpret_cast<Virtio::Qword *>(&qc->desc_addr))->w[i] = value;
          break;
        }

      case Virtio::Hdr_off_queue_avail_low:
      case Virtio::Hdr_off_queue_avail_high:
        {
          int i = reg == Virtio::Hdr_off_queue_avail_low ? 0 : 1;
          (reinterpret_cast<Virtio::Qword *>(&vcfg->queue_avail))->w[i] = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            (reinterpret_cast<Virtio::Qword *>(&qc->avail_addr))->w[i] = value;
          break;
        }

      case Virtio::Hdr_off_queue_used_low:
      case Virtio::Hdr_off_queue_used_high:
        {
          int i = reg == Virtio::Hdr_off_queue_used_low ? 0 : 1;
          (reinterpret_cast<Virtio::Qword *>(&vcfg->queue_used))->w[i] = value;
          auto *qc = dev()->current_virtqueue_config();
          if (qc)
            (reinterpret_cast<Virtio::Qword *>(&qc->used_addr))->w[i] = value;
          break;
        }
      }
  }

private:
  DEV *dev()
  { return static_cast<DEV *>(this); }
};

}
