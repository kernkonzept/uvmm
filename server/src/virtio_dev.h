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

  Virtqueue()
  { memset(&config, 0, sizeof(config)); }

  void init_queue(void *base)
  { setup(config.num, config.align, base); }

};


class Dev : public Vdev::Device
{
public:
  typedef L4virtio::Svr::Dev_status Status;
  typedef L4virtio::Svr::Dev_features Features;

protected:
  l4_uint32_t _vendor;
  l4_uint32_t _device;
  l4_uint32_t _irq_status;
  Status _status;
  l4_uint32_t _guest_features[8];

  Vmm::Vm_ram *_iommu;

public:
  Dev(Vmm::Vm_ram *iommu, l4_uint32_t vendor, l4_uint32_t device)
  : _vendor(vendor), _device(device), _irq_status(0), _status(0),
    _iommu(iommu)
  {
    memset(_guest_features, 0, sizeof(_guest_features));
  }

  virtual l4_uint32_t read_config(unsigned /*reg*/) { return 0; }
  virtual void write_config(unsigned /*reg*/, l4_uint32_t /*value*/) {}
  virtual void kick() = 0;
  virtual void irq_ack(int /*value*/) {}
  virtual l4_uint32_t host_feature(unsigned /*id*/) { return 0; }
  virtual Virtqueue *queue(unsigned idx) = 0;
  virtual void reset() {}

  l4_uint32_t vendor() const noexcept
  { return _vendor; }

  l4_uint32_t device() const noexcept
  { return _device; }

  l4_uint32_t irq_status()
  {
    // hack: we have always a queue IRQ
    return 1;
    if (0)
      {
        l4_uint32_t tmp = _irq_status;
        _irq_status = 0;
        return tmp;
      }
  }

  Status dev_status() const noexcept
  { return _status; }

  void set_dev_status(l4_uint32_t status)
  {
    _status.raw = status;
    if (status == 0)
      reset();
  }

  l4_uint32_t guest_feature(unsigned idx) noexcept
  { return (idx < 8) ? _guest_features[idx] : 0; }

  void set_guest_feature(unsigned idx, l4_uint32_t value) noexcept
  {
    if (idx < 8)
      _guest_features[idx] = value;
  }

  template<typename T>
  T *devaddr_to_virt(l4_addr_t devaddr) const
  { return _iommu->access(L4virtio::Ptr<T>(devaddr)); }
};


template<typename DEV>
class Mmio_connector
{
public:
  l4_uint32_t read(unsigned reg, char /*size*/, unsigned)
  {
    if (reg >= 0x100)
      return dev()->read_config(reg - 0x100);

    switch (reg >> 2)
      {
      case 0: return *reinterpret_cast<l4_uint32_t const *>("virt");
      case 1: return 1;
      case 2: return dev()->device();
      case 3: return dev()->vendor();
      case 4: return dev()->host_feature(_current_host_feat);
      case 13: return _current_q ? _current_q->config.num_max : 0;
      case 16: return _current_q ? _current_q->config.pfn : 0;
      case 24: return dev()->irq_status();
      case 28: return dev()->dev_status().raw;
      }
    return ~0U;
  }

  void write(unsigned reg, char /*size*/, l4_uint32_t value, unsigned)
  {
    if (reg >= 0x100)
      {
        dev()->write_config(reg - 0x100, value);
        return;
      }

    switch (reg >> 2)
      {
      case 5:
        _current_host_feat = value;
        break;

      case 8:
        dev()->set_guest_feature(_current_guest_feat, value);
        break;

      case 9:
        _current_guest_feat = value;
        break;

      case 10:
        _page_size = value;
        break;

      case 12:
        _current_q = dev()->queue(value);
        break;

      case 14:
        if (_current_q)
          _current_q->config.num = _current_q->config.num_max >= value
                                    ? value
                                    : _current_q->config.num_max;
        break;

      case 15:
        if (_current_q)
          _current_q->config.align = value;
        break;

      case 16:
        if (_current_q)
          {
            _current_q->config.pfn = value;
            _current_q->init_queue(dev()->template devaddr_to_virt<void>(value * _page_size));
          }
        break;

      case 20:
        dev()->kick();
        break;

      case 25:
        dev()->irq_ack(value);
        break;

      case 28:
        dev()->set_dev_status(value);
        break;
      }
  }

private:
  DEV *dev()
  { return static_cast<DEV *>(this); }

  Virtqueue *_current_q = 0;
  unsigned _current_host_feat = 0;
  unsigned _current_guest_feat = 0;
  l4_uint32_t _page_size = 1 << 12;
};

}
