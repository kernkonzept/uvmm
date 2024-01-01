/*
 * Copyright (C) 2017-2020, 2022-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/re/util/cap_alloc>
#include <l4/re/dataspace>
#include <l4/re/env>
#include <l4/re/error_helper>

#include <l4/l4virtio/virtio.h>
#include <l4/l4virtio/server/virtio>
#include <l4/l4virtio/server/l4virtio>

#include "debug.h"
#include "irq_dt.h"
#include "mmio_device.h"
#include "virtio_device_mem_pool.h"

namespace Vdev {

/**
 * Virtio proxy for a device exported from the VMM.
 *
 * The device allocates a page for the L4virtio config page and maps it
 * read-only into the guest at the first reg address configured in the
 * device tree. The page is initially empty. The guest is expected to fill
 * in the initial device information and at the very end write the magic
 * value indicating that the config page is ready. At this point the
 * proxy will allow a client to register itself.
 *
 * The device tree must provide a second address for a l4 specific config page.
 * This will be used for the guest memory configuration.
 *
 * set_status and config_queue use the standard cmd configuration interface
 * of the L4virtio protocol.
 *
 * Kicks by the driver are forwarded as notification interrupts to the guest.
 * The guest must acknowledge all interrupts by writing 0 to the cmd field
 * in the config page.
 *
 * The guest device may notify the driver about queue changes by writing
 * the appropriate driver_notify_index of the queue to the queue_notify field.
 */
class Virtio_device_proxy_base
: public Vmm::Read_mapped_mmio_device_t<Virtio_device_proxy_base,
                                        l4virtio_config_hdr_t>,
  public L4::Epiface_t<Virtio_device_proxy_base, L4virtio::Device>,
  public Vdev::Device
{
  enum
  {
    L4VHOST_MAX_MEM_REGIONS = 8
  };

  struct Host_irq : public L4::Irqep_t<Host_irq>
  {
    explicit Host_irq(Virtio_device_proxy_base *s) : s(s) {}
    Virtio_device_proxy_base *s;
    void handle_irq() { s->irq_kick(); }
  };

  struct L4_region_config
  {
    // C type shared with guest
    struct Region_config_t
    {
      l4_uint32_t num;
      struct
      {
        l4_uint64_t phys;
        l4_uint64_t size;
        l4_uint64_t base;
      } region[L4VHOST_MAX_MEM_REGIONS];
    };

    L4_region_config(l4_uint64_t size)
    {
      auto *e = L4Re::Env::env();
      auto ds = L4Re::chkcap(L4Re::Util::make_unique_del_cap<L4Re::Dataspace>(),
                             "Allocate Virtio::Dev dataspace capability.");

      L4Re::chksys(e->mem_alloc()->alloc(size, ds.get()),
                   "Allocate Virtio::Dev configuration memory.");

      ds_mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Virtio_device_proxy: l4 cfg",
                                                  ds.get(), 0, size,
                                                  L4Re::Rm::F::RW |
                                                  L4Re::Rm::F::Cache_uncached);
      ds_hdlr = Vdev::make_device<Ds_handler>(ds_mgr, L4_FPAGE_RO);

      cfg_ds = std::move(ds);

      get()->num = 0;
    }

    Region_config_t *get()
    { return ds_mgr->local_addr<Region_config_t*>(); }

    int add_region(Vmm::Region const &region, l4_uint64_t base)
    {
      auto c = get();
      if (c->num >= L4VHOST_MAX_MEM_REGIONS)
        return -L4_EINVAL;

      c->region[c->num].phys = region.start.get();
      c->region[c->num].size = region.end - region.start + 1;
      c->region[c->num].base = base;
      ++(c->num);

      return L4_EOK;
    }

    cxx::Ref_ptr<Ds_handler> ds_hdlr;
    cxx::Ref_ptr<Vmm::Ds_manager> ds_mgr;
    L4Re::Util::Unique_del_cap<L4Re::Dataspace> cfg_ds;
  };

public:
  Virtio_device_proxy_base(L4::Cap<L4::Rcv_endpoint> ep,
                           l4_size_t cfg_size, l4_uint64_t l4cfg_size,
                           Vmm::Guest *vmm,
                           cxx::Ref_ptr<Virtio_device_mem_pool> mempool)
  : Read_mapped_mmio_device_t("Virtio_device_proxy: vio cfg", cfg_size,
                              L4Re::Rm::F::Cache_normal),
    _host_irq(this), _ep(ep),
    _vmm(vmm),
    _l4cfg(l4cfg_size),
    _mempool(mempool)
  {
    // Make sure the receive window of the main cpu server loop is large
    // enough. Other VMs may already wait in the kernel to connect to this vio
    // cap. We have to make sure the receive window has enough space for the
    // RAM cap before we ever call wait_for_ipc.
    Vmm::Generic_cpu_dev::main_vcpu().get_bm()->alloc_buffer_demand(
      get_buffer_demand());
  }

  virtual void irq_kick() = 0;
  virtual void irq_ack() {}

  void write(unsigned reg, char width, l4_umword_t value, unsigned cpu_id)
  {
    (void) cpu_id;

    l4_addr_t l = (l4_addr_t) mmio_local_addr() + reg;

    // only naturally aligned 32bit accesses are allowed
    if (L4_UNLIKELY(l & ((1UL << width) - 1)))
      return;

    l4_uint32_t old_value = 0;
    if (reg == offsetof(l4virtio_config_hdr_t, cmd) ||
        reg == offsetof(l4virtio_config_hdr_t, magic))
      old_value = *reinterpret_cast<l4_uint32_t *>(l);
    else if (reg == offsetof(l4virtio_config_hdr_t, queue_notify))
      {
        // Acknowledge earlier queue irqs
        irq_ack();
        // Now kick the driver
        mmio_local_addr()->irq_status |= L4VIRTIO_IRQ_STATUS_VRING;
        _kick_guest_irq->trigger();
        return; // do not actually write the value
      }

    Vmm::Mem_access::write_width(l, value, width);

    if (reg >= 0x100)
      {
        // The guest accessed the device specific config. Make sure the cache
        // is cleaned.
        Vmm::Mem_access::cache_clean_data_width(l, width);
        return;
      }

    switch (reg)
      {
      case offsetof(l4virtio_config_hdr_t, magic):
        if (old_value == L4VIRTIO_MAGIC)
          {
            warn.printf("Virtio magic value overwritten. Reset is not handled.\n");
            return;
          }

        if (value == L4VIRTIO_MAGIC)
          {
            trace.printf("Starting up vio server\n");
            _vmm->registry()->register_irq_obj(&_host_irq);
            _vmm->registry()->register_obj(this, _ep);
          }
        break;
      case offsetof(l4virtio_config_hdr_t, cmd):
        if (value == 0)
          {
            if (old_value & L4VIRTIO_CMD_MASK)
              {
                L4virtio::wmb();
                mmio_local_addr()->irq_status |= L4VIRTIO_IRQ_STATUS_VRING;
                _kick_guest_irq->trigger();
              }

            irq_ack();
          }
        break;
      }
  }

  long op_register_ds(L4virtio::Device::Rights,
                      L4::Ipc::Snd_fpage ds_cap_fp, l4_uint64_t ds_base,
                      l4_umword_t offset, l4_umword_t sz)
  {
    trace.printf("Registering dataspace from 0x%llx with %lu KiB, offset 0x%lx\n",
                 ds_base, sz >> 10, offset);

    if (!ds_cap_fp.cap_received())
      return -L4_EINVAL;

    auto ds = L4::Epiface::server_iface()->rcv_cap<L4Re::Dataspace>(0);
    if (!ds.is_valid())
      return -L4_EINVAL;

    long err = L4::Epiface::server_iface()->realloc_rcv_cap(0);
    if (err < 0)
      return err;

    return _l4cfg.add_region(_mempool->register_ds(ds, ds_base, offset, sz),
                             ds_base);
  }

  long op_set_status(L4virtio::Device::Rights, unsigned)
  {
    warn.printf("Client uses IPC notification protocol. Not supported.\n");
    return -L4_EINVAL;
  }

  long op_config_queue(L4virtio::Device::Rights, unsigned)
  {
    warn.printf("Client uses IPC notification protocol. Not supported.\n");
    return -L4_EINVAL;
  }

  long op_device_config(L4virtio::Device::Rights,
                        L4::Ipc::Cap<L4Re::Dataspace> &config_ds,
                        l4_addr_t &ds_offset)
  {
    config_ds = L4::Ipc::make_cap(mmio_ds(), L4_CAP_FPAGE_RW);
    ds_offset = 0;
    return L4_EOK;
  }

  long op_device_notification_irq(L4virtio::Device::Rights,
                                  unsigned index,
                                  L4::Ipc::Cap<L4::Triggerable> &irq)
  {
    if (index != 0)
      return -L4_EINVAL;

    irq = L4::Ipc::make_cap(_host_irq.obj_cap(), L4_CAP_FPAGE_RO);
    return L4_EOK;
  }

  int op_bind(L4::Icu::Rights, l4_umword_t idx, L4::Ipc::Snd_fpage irq_cap_fp)
  {
    if (idx != 0)
      return -L4_EINVAL;

    if (!irq_cap_fp.cap_received())
      return -L4_EINVAL;

    _kick_guest_irq = L4Re::Util::Unique_cap<L4::Irq>(
      server_iface()->rcv_cap<L4::Irq>(0));
    if (!_kick_guest_irq.is_valid())
      return -L4_EINVAL;

    return server_iface()->realloc_rcv_cap(0);
  }

  int op_unbind(L4::Icu::Rights, l4_umword_t, L4::Ipc::Snd_fpage)
  { return -L4_ENOSYS; }

  int op_info(L4::Icu::Rights, L4::Icu::_Info &icu_info)
  {
    icu_info.features = 0;
    icu_info.nr_irqs = 1;
    icu_info.nr_msis = 0;

    return L4_EOK;
  }

  int op_msi_info(L4::Icu::Rights, l4_umword_t, l4_uint64_t, l4_icu_msi_info_t &)
  { return -L4_ENOSYS; }

  int op_mask(L4::Icu::Rights, l4_umword_t)
  { return -L4_ENOSYS; }

  int op_unmask(L4::Icu::Rights, l4_umword_t)
  { return -L4_ENOREPLY; }

  int op_set_mode(L4::Icu::Rights, l4_umword_t, l4_umword_t)
  { return -L4_ENOSYS; }

protected:
  L4Re::Util::Unique_cap<L4::Irq> _kick_guest_irq;
  Host_irq _host_irq;

  L4::Cap<L4::Rcv_endpoint> _ep;

  Vmm::Guest *_vmm; // needed for registering DS handlers
  L4_region_config _l4cfg;
  cxx::Ref_ptr<Virtio_device_mem_pool> _mempool;

private:
  Dbg trace = {Dbg::Dev, Dbg::Trace, "viodev"};
  Dbg warn = {Dbg::Dev, Dbg::Warn, "viodev"};
  Dbg info = {Dbg::Dev, Dbg::Info, "viodev"};
};

}
