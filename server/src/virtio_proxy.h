/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstring>

#include <l4/sys/capability>
#include <l4/sys/meta>

#include <l4/re/dataspace>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/rm>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>

#include <l4/l4virtio/l4virtio>
#include <l4/l4virtio/virtqueue>

#include "irq.h"
#include "guest.h"
#include "mmio_device.h"
#include "virtio_event_connector.h"
#include "vm_ram.h"

namespace L4virtio { namespace Driver {

/**
 * \brief Client-side implementation for a general virtio device.
 */
class Device
{
public:
  Device(l4_size_t config_size)
  : _config_page_size(config_size)
  {}

  /**
   * Contacts the device and sets up the config page.
   *
   * \param srvcap    Capability for device communication.
   * \param guest_irq Irq capability to send to device.
   *
   * \throws L4::Runtime_error if the initialisation fails
   *
   * This function contacts the server, sets up the notification
   * channels and the configuration dataspace. After this is done,
   * the caller can set up any dataspaces it needs.
   */
  void driver_connect(L4::Cap<L4virtio::Device> srvcap,
                      L4::Cap<L4::Irq> guest_irq)
  {
    _device = srvcap;

    _host_irq = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                             "Allocating cap for host irq");

    _config_cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
                               "Allocating cap for config dataspace");

    L4Re::chksys(_device->register_iface(guest_irq, _host_irq.get(),
                                         _config_cap.get()),
                 "Registering interface with device");

    L4Re::Dataspace::Stats stats;
    L4Re::chksys(_config_cap->info(&stats),
                 "Determining size of virtio config page");
    if (stats.size < _config_page_size)
      L4Re::chksys(-L4_ENODEV, "Virtio config space too small");

    auto *e = L4Re::Env::env();
    L4Re::chksys(e->rm()->attach(&_config, _config_page_size,
                                 L4Re::Rm::Search_addr,
                                 L4::Ipc::make_cap_rw(_config_cap.get())),
                 "Attaching config dataspace");

    if (memcmp(&_config->magic, "virt", 4) != 0)
      L4Re::chksys(-L4_ENODEV, "Device config has wrong magic value");

    if (_config->version != 2)
      L4Re::chksys(-L4_ENODEV, "Require virtio version of 2");
  }


  /**
   * Share a dataspace with the device.
   *
   * \param ds      Dataspace to share with the device.
   * \param offset  Offset in dataspace where the shared part starts.
   * \param size    Total size in bytes of the shared space.
   * \param devaddr Start of shared space in the device address space.
   *
   * Although this function allows to share only a part of the given dataspace
   * for convenience, the granularity of sharing is always the dataspace level.
   * Thus, the remainder of the dataspace is not protected from the device.
   */
  int register_ds(L4::Cap<L4Re::Dataspace> ds, l4_umword_t offset,
                  l4_umword_t size, l4_uint64_t devaddr)
  {
    return _device->register_ds(L4::Ipc::make_cap_rw(ds), devaddr, offset, size);
  }

  int config_queue(int num)
  {
    if (l4virtio_get_feature(_config->dev_features_map,
                             L4VIRTIO_FEATURE_CMD_CONFIG))
      return _config->config_queue(num, _host_irq.get(), _guest_irq.get());
    else
      return _device->config_queue(num);
  }

  L4virtio::Device::Config_hdr *device_config() const
  { return _config.get(); }

  L4::Cap<L4Re::Dataspace> config_ds() const
  { return _config_cap.get(); }

  l4_uint32_t config_size() const
  { return _config_page_size; }

  L4virtio::Device::Config_queue *queue_config(int num) const
  { return &_config->queues()[num]; }

  void virtio_queue_notify(unsigned)
  { _host_irq->trigger(); }

  void set_status(l4_uint32_t status)
  {
    bool use_irq = l4virtio_get_feature(_config->dev_features_map,
                                        L4VIRTIO_FEATURE_CMD_CONFIG);

    if (use_irq
        && status == (L4VIRTIO_STATUS_ACKNOWLEDGE | L4VIRTIO_STATUS_DRIVER
                      | L4VIRTIO_STATUS_FEATURES_OK))
      l4virtio_set_feature(_config->driver_features_map,
                           L4VIRTIO_FEATURE_CMD_CONFIG);

    if (use_irq)
      _config->set_status(status, _host_irq.get(), _guest_irq.get());
    else
      _device->set_status(status);
  }

  ~Device()
  {
    if (!_config.get())
      return;

    set_status(0); // reset
    for (l4_uint32_t i = 0; i < _config->num_queues; ++i)
      {
        _config->queues()[i].num = 0;
        _config->queues()[i].ready = 0;
        config_queue(i);
      }
  }

  l4_uint32_t irq_status() const { return _config->irq_status; }

protected:
  L4::Cap<L4virtio::Device> _device;
  L4Re::Rm::Unique_region<L4virtio::Device::Config_hdr *> _config;
  L4Re::Util::Unique_cap<L4::Irq> _guest_irq;

private:
  L4Re::Util::Unique_cap<L4::Irq> _host_irq;
  L4Re::Util::Unique_cap<L4Re::Dataspace> _config_cap;

  unsigned _config_page_size = 0;
};

} } // namespace

namespace Vdev {

template <typename DEV>
class Virtio_proxy
: public L4::Irqep_t<Virtio_proxy<DEV>>,
  public Device
{
private:
  /**
   * Number of no-notify queue.
   *
   * A no-notify-queue requests no_notify_host when busy. Useful in
   * particualar for send queues in network devices. Enable via
   * device tree configuration l4vmm,no-notify = <queue-id>;
   */
  unsigned _nnq_id = -1U;
  L4virtio::Driver::Virtqueue _nnq;
  l4_uint32_t _irq_status_shadow = 0;

public:
  Virtio_proxy(l4_size_t config_size)
  : _dev(config_size)
  {}

  void init_device(Vdev::Device_lookup const *devs,
                   Vdev::Dt_node const &self) override
  {
    int err = dev()->event_connector()->init_irqs(devs, self);
    if (err < 0)
      Dbg(Dbg::Dev, Dbg::Warn, "virtio")
        .printf("Cannot connect virtio IRQ: %d\n", err);

    int sz;
    auto const *prop = self.get_prop<fdt32_t>("l4vmm,no-notify", &sz);
    if (prop && sz > 0)
      _nnq_id = fdt32_to_cpu(*prop);

    auto *ram = devs->ram().get();
    L4Re::chksys(_dev.register_ds(ram->ram(), 0, ram->size(),
                                  ram->vm_start()),
                 "Registering RAM for virtio proxy");
  }

  void register_irq(L4::Registry_iface *registry, L4::Cap<L4virtio::Device> host)
  {
    L4::Cap<L4::Irq> guest_irq = L4Re::chkcap(registry->register_irq_obj(this),
                                              "Registering guest IRQ in proxy");

    _dev.driver_connect(host, guest_irq);
  }

  void handle_irq()
  {
    Virtio::Event_set ev;
    // FIXME: our L4 transport supports just a single IRQ, so trigger event 1
    //        for all queues until we implemented per-queue events.
    //        And use event index 0 for config events.
    auto s = 1; // FIXME: correctly set irq_status in devices: _dev.irq_status();
    if (s & 1)
      ev.set(1); // set event index 1 for all queue events

    if (s & 2)
      ev.set(0);

    _irq_status_shadow |= 1;
    if (_dev.device_config()->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->send_events(cxx::move(ev));
  }

  void virtio_irq_ack(unsigned val)
  {
    _irq_status_shadow &= ~val;
    if (_dev.device_config()->irq_status != _irq_status_shadow)
      dev()->set_irq_status(_irq_status_shadow);

    dev()->event_connector()->clear_events(val);
  }

  l4virtio_config_hdr_t *mmio_local_addr() const
  { return _dev.device_config(); }

  l4_size_t mapped_mmio_size() const
  { return l4_round_page(_dev.config_size()); }

  L4::Cap<L4Re::Dataspace> mmio_ds() const
  { return _dev.config_ds(); }

  l4virtio_config_hdr_t *virtio_cfg()
  { return _dev.device_config(); }

  void virtio_device_config_written(unsigned)
  {}

  L4virtio::Device::Config_queue *current_virtqueue_config()
  {
    unsigned qn = _dev.device_config()->queue_sel;
    if (qn >= _dev.device_config()->num_queues)
      return nullptr;

    return _dev.queue_config(qn);
  }

  void virtio_queue_ready(unsigned ready)
  {
    auto *cfg = _dev.device_config();
    unsigned qn = cfg->queue_sel;

    if (qn >= cfg->num_queues)
      return;

    if (ready != 1 && ready != 0)
      return;

    auto *q = _dev.queue_config(qn);
    if (ready == q->ready)
      return;

    q->ready = ready;

    _dev.config_queue(qn);
  }

  void virtio_queue_notify(unsigned q)
  { _dev.virtio_queue_notify(q); }

  void virtio_set_status(l4_uint32_t status)
  { _dev.set_status(status); }

private:
  DEV *dev() { return static_cast<DEV *>(this); }

  L4virtio::Driver::Device _dev;
};

class Virtio_proxy_mmio
: public Virtio_proxy<Virtio_proxy_mmio>,
  public Vmm::Ro_ds_mapper_t<Virtio_proxy_mmio>,
  public Virtio::Mmio_connector<Virtio_proxy_mmio>
{
public:
  Virtio_proxy_mmio(l4_size_t config_size)
  : Virtio_proxy<Virtio_proxy_mmio>(config_size)
  {}

  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

private:
  Virtio::Event_connector_irq _evcon;
};

}
