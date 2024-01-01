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
#include <l4/re/util/unique_cap>

#include <l4/l4virtio/l4virtio>
#include <l4/l4virtio/virtqueue>

#include "irq.h"
#include "guest.h"
#include "mmio_device.h"
#include "virtio_event_connector.h"
#include "vm_ram.h"
#include "monitor/virtio_cmd_handler.h"

namespace L4virtio { namespace Driver {

/**
 * \brief Client-side implementation for a general virtio device.
 */
class Device
{
public:
  Device(L4::Cap<L4virtio::Device> device, l4_size_t config_size)
  : _device(device), _config_page_size(config_size)
  {}

  /**
   * Contacts the device and sets up the config page.
   *
   * \param guest_irq Irq capability to send to device.
   *
   * \throws L4::Runtime_error if the initialisation fails
   *
   * This function contacts the server, sets up the notification
   * channels and the configuration dataspace. After this is done,
   * the caller can set up any dataspaces it needs.
   */
  void driver_connect(L4::Cap<L4::Irq> guest_irq)
  {
    auto vicu = L4::cap_dynamic_cast<L4::Icu>(_device);

    if (!vicu.is_valid())
      L4Re::chksys(-L4_ENOSYS,
                   "ICU protocol not supported by virtio device. Legacy interface?");

    l4_icu_info_t icu_info;
    L4Re::chksys(vicu->info(&icu_info), "Get info about ICU.");

    _config_cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
                               "Allocating cap for config dataspace");

    l4_addr_t ds_offset;
    L4Re::chksys(_device->device_config(_config_cap.get(), &ds_offset),
                 "Request device config page");

    L4Re::Dataspace::Stats stats;
    auto ret = _config_cap->info(&stats);
    if ((ret != -L4_ENOSYS)
         && (ret != L4_EOK || stats.size < _config_page_size + ds_offset))
      L4Re::chksys(-L4_ENODEV, "Virtio config space too small");

    auto *e = L4Re::Env::env();
    L4Re::chksys(e->rm()->attach(&_config, _config_page_size,
                                 L4Re::Rm::F::Search_addr | L4Re::Rm::F::Eager_map
                                 | L4Re::Rm::F::RW,
                                 L4::Ipc::make_cap_rw(_config_cap.get()),
                                 ds_offset),
                 "Attaching config dataspace");

    if (memcmp(&_config->magic, "virt", 4) != 0)
      L4Re::chksys(-L4_ENODEV, "Device config has wrong magic value");

    if (_config->version != 2)
      L4Re::chksys(-L4_ENODEV, "Require virtio version of 2");

    _guest_irq = guest_irq;

    _host_irq = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                             "Allocating cap for host irq");

    _config->cfg_driver_notify_index = 0;

    if (icu_info.nr_irqs > 0)
      L4Re::chksys(vicu->bind(0, guest_irq),
                   "Send notification IRQ to device");

    ret = _device->device_notification_irq(_config->cfg_device_notify_index,
                                           _host_irq.get());

    if (ret != L4_EOK && ret != -L4_ENOSYS)
      L4Re::chksys(ret, "Receive notification IRQ from device");

    _queue_irqs.resize(_config->num_queues);

    // Flush initial config page content
    l4_cache_clean_data(reinterpret_cast<l4_addr_t>(_config.get()),
                        reinterpret_cast<l4_addr_t>(_config.get())
                        + _config_page_size);
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

  int config_queue(unsigned num)
  {
    if (l4virtio_get_feature(_config->dev_features_map,
                             L4VIRTIO_FEATURE_CMD_CONFIG))
      // Do busy waiting, because the irq could arrive on any CPU
      return _config->config_queue(num, _host_irq.get(), L4::Cap<L4::Triggerable>());

    _config->queues()[num].driver_notify_index = 0;

    if (_queue_irqs.size() <= num)
      _queue_irqs.resize(num + 1);
    else
      _queue_irqs[num].reset();

    int ret = _device->config_queue(num);

    if (ret >= 0 && _config->queues()[num].ready)
      {
        l4_uint16_t irq = _config->queues()[num].device_notify_index;
        auto cap = L4Re::Util::make_unique_cap<L4::Irq>();
        if (_device->device_notification_irq(irq, cap.get()) >= 0)
          _queue_irqs[num] = std::move(cap);
      }

    return ret;
  }

  L4virtio::Device::Config_hdr *device_config() const
  { return _config.get(); }

  L4::Cap<L4Re::Dataspace> config_ds() const
  { return _config_cap.get(); }

  l4_uint32_t config_size() const
  { return _config_page_size; }

  L4virtio::Device::Config_queue *queue_config(int num) const
  { return &_config->queues()[num]; }

  void virtio_queue_notify(unsigned num)
  {
    if (l4virtio_get_feature(_config->dev_features_map,
                             L4VIRTIO_FEATURE_CMD_CONFIG))
      // Do busy waiting, because the irq could arrive on any CPU
      _config->notify_queue(num, _host_irq.get(), L4::Cap<L4::Triggerable>());
    else if (num < _queue_irqs.size())
      _queue_irqs[num]->trigger();
  }

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
      // Do busy waiting, because the irq could arrive on any CPU
      _config->set_status(status, _host_irq.get(), L4::Cap<L4::Triggerable>());
    else
      _device->set_status(status);
  }

  void cfg_changed(unsigned reg)
  {
    bool use_irq = l4virtio_get_feature(_config->dev_features_map,
                                        L4VIRTIO_FEATURE_CMD_CONFIG);

    if (use_irq)
      // Do busy waiting, because the irq could arrive on any CPU
      _config->cfg_changed(reg, _host_irq.get(), L4::Cap<L4::Triggerable>());
    else
      L4Re::throw_error(-L4_EINVAL, "Direct config change not supported in L4Virtio protocol.");
  }

  ~Device()
  {
    if (!_config.get())
      return;

    set_status(0); // reset
  }

  l4_uint32_t irq_status() const { return _config->irq_status; }

protected:
  L4::Cap<L4virtio::Device> _device;
  L4Re::Rm::Unique_region<L4virtio::Device::Config_hdr *> _config;
  L4::Cap<L4::Irq> _guest_irq;

private:
  std::vector<L4Re::Util::Unique_cap<L4::Irq> > _queue_irqs;
  L4Re::Util::Unique_cap<L4::Irq> _host_irq;
  L4Re::Util::Unique_cap<L4Re::Dataspace> _config_cap;

  unsigned _config_page_size = 0;
};

} } // namespace

namespace Vdev {

template <typename DEV>
class Virtio_proxy
: public L4::Irqep_t<Virtio_proxy<DEV>>,
  public Device,
  public Monitor::Virtio_proxy_cmd_handler<Monitor::Enabled, Virtio_proxy<DEV>>
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
  Virtio_proxy(L4::Cap<L4virtio::Device> device, l4_size_t config_size,
               unsigned nnq_id, Vmm::Vm_ram *ram)
  : _nnq_id(nnq_id), _dev(device, config_size)
  {
    ram->foreach_region([this](Vmm::Ram_ds const &r)
      {
        L4Re::chksys(_dev.register_ds(r.ds(), r.ds_offset(), r.size(),
                                      r.vm_start().get()),
                     "Registering RAM for virtio proxy");
      });
  }

  int init_irqs(Vdev::Device_lookup *devs, Vdev::Dt_node const &self)
  { return dev()->event_connector()->init_irqs(devs, self); }

  void register_irq(L4::Registry_iface *registry)
  {
    L4::Cap<L4::Irq> guest_irq = L4Re::chkcap(registry->register_irq_obj(this),
                                              "Registering guest IRQ in proxy");

    _dev.driver_connect(guest_irq);

    // Unmask it, this might be a hardware interrupt.
    guest_irq->unmask();
  }

  void handle_irq()
  {
    Virtio::Event_set ev;
    // FIXME: our L4 transport supports just a single IRQ, so trigger event 1
    //        for all queues until we implemented per-queue events.
    //        And use event index 0 for config events.
    auto s = _dev.device_config()->irq_status;
    if (s & L4VIRTIO_IRQ_STATUS_CONFIG)
      {
        _irq_status_shadow |= L4VIRTIO_IRQ_STATUS_CONFIG;
        ev.set(0);
      }
    if (s & L4VIRTIO_IRQ_STATUS_VRING)
      {
        _irq_status_shadow |= L4VIRTIO_IRQ_STATUS_VRING;
        ev.set(1); // set event index 1 for all queue events
      }

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

  void virtio_device_config_written(unsigned reg)
  { _dev.cfg_changed(reg); }

  L4virtio::Device::Config_queue *virtqueue_config(unsigned qn)
  {
    if (qn >= _dev.device_config()->num_queues)
      return nullptr;

    return _dev.queue_config(qn);
  }

  L4virtio::Device::Config_queue *current_virtqueue_config()
  {
    return virtqueue_config(_dev.device_config()->queue_sel);
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
  Virtio_proxy_mmio(L4::Cap<L4virtio::Device> device, l4_size_t config_size,
                    unsigned nnq_id, Vmm::Vm_ram *ram)
  : Virtio_proxy<Virtio_proxy_mmio>(device, config_size, nnq_id, ram)
  {}

  Virtio::Event_connector_irq *event_connector() { return &_evcon; }

  char const *dev_name() const override { return "Virtio_proxy_mmio"; }

private:
  Virtio::Event_connector_irq _evcon;
};

}
