/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/util/cap_alloc>
#include <l4/re/dataspace>
#include <l4/re/env>
#include <l4/re/error_helper>

#include <l4/l4virtio/virtio.h>
#include <l4/l4virtio/server/virtio>
#include <l4/l4virtio/server/l4virtio>

#include "debug.h"
#include "device_factory.h"
#include "guest.h"
#include "mmio_device.h"

namespace {

using namespace Vdev;

static Dbg trace(Dbg::Dev, Dbg::Trace, "VioDrv");
static Dbg warn(Dbg::Dev, Dbg::Warn, "VioDrv");
static Dbg info(Dbg::Dev, Dbg::Info, "VioDrv");

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
 * The device tree must provide a second address range in the reg property
 * where the client dataspaces will be mapped to. Currently the device
 * address will be used directly as offset into this address range. Note
 * that this effectively means that only clients are possible that
 * use a small or zero offset when registering dataspaces.
 * TODO: make sure guest does not fail if an address in this window is
 * not mapped.
 *
 * set_status and config_queue use the standard cmd configuration interface
 * of the L4virtio protocol.
 *
 * Kicks by the driver are forwarded as notification interrupts to the guest.
 * The guest must acknowledge all interupts by writing 0 to the cmd field
 * in the config page.
 *
 * The guest device may notify the driver about queue changes by writing
 * the appropriate driver_notify_index of the queue to the queue_notify field.
 */
class Virtio_device_proxy
: public Vmm::Read_mapped_mmio_device_t<Virtio_device_proxy, l4virtio_config_hdr_t>,
  public L4::Epiface_t<Virtio_device_proxy, L4virtio::Device>,
  public Vdev::Device
{
  struct Host_irq : public L4::Irqep_t<Host_irq>
  {
    explicit Host_irq(Virtio_device_proxy *s) : s(s) {}
    Virtio_device_proxy *s;
    void handle_irq() { s->kick(); }
  };


public:
  Virtio_device_proxy(char const *service, l4_size_t cfg_size)
  : Read_mapped_mmio_device_t(cfg_size, L4Re::Rm::Cache_normal),
    _host_irq(this), _ack_pending(false)
  {
    info.printf("New Virtio_proxy_mapper size 0x%zx\n", cfg_size);
    assert(strlen(service) < sizeof(_service_name));
    strcpy(_service_name, service);
  }

  void init_device(Vdev::Device_lookup const *devs,
                   Vdev::Dt_node const &self) override
  {
    auto irq_ctl = self.find_irq_parent();
    if (!irq_ctl.is_valid())
      L4Re::chksys(-L4_ENODEV, "Interrupt handler for virtio console not found.\n");

    // XXX need dynamic cast for Ref_ptr here
    auto *ic = dynamic_cast<Gic::Ic *>(devs->device_from_node(irq_ctl).get());

    if (!ic)
      L4Re::chksys(-L4_ENODEV, "Interrupt handler for virtio console has bad type.\n");

    _irq_sink.rebind(ic, ic->dt_get_interrupt(self, 0));

    if (self.get_reg_val(1, &_drvmem_base, &_drvmem_size) < 0)
      {
        warn.printf("Reg entry for driver window not found.\n");
        _drvmem_size = 0;
      }

    l4virtio_set_feature(mmio_local_addr()->dev_features_map,
                         L4VIRTIO_FEATURE_VERSION_1);
    l4virtio_set_feature(mmio_local_addr()->dev_features_map,
                         L4VIRTIO_FEATURE_CMD_CONFIG);

    _vmm = devs->vmm();
  }

  void write(unsigned reg, char width, l4_umword_t value, unsigned cpu_id)
  {
    (void) cpu_id;

    l4_addr_t l = (l4_addr_t) mmio_local_addr() + reg;

    // only naturally aligned 32bit accesses are allowed
    if (L4_UNLIKELY(l & ((1UL << width) - 1)))
      return;

    l4_uint32_t old_value = 0;
    if (reg == 0xf8 || reg == 0)
      old_value = *reinterpret_cast<l4_uint32_t *>(l);
    else if (reg == 0x50) // queue notify
      {
        _kick_guest_irq->trigger();
        return; // do not actually write the value
      }

    switch (width)
      {
      case Vmm::Mem_access::Wd8:
        *reinterpret_cast<l4_uint8_t *>(l) = value;
        break;
      case Vmm::Mem_access::Wd16:
        *reinterpret_cast<l4_uint16_t *>(l) = value;
        break;
      case Vmm::Mem_access::Wd32:
        *reinterpret_cast<l4_uint32_t *>(l) = value;
        break;
      case Vmm::Mem_access::Wd64:
        *reinterpret_cast<l4_uint64_t *>(l) = value;
        break;
      }

    switch (reg)
      {
      case 0:
        if (old_value == L4VIRTIO_MAGIC)
          {
            L4Re::chksys(-L4_EINVAL, "Virtio magic value overwritten.\n");
          }

        if (value == L4VIRTIO_MAGIC)
          {
            trace.printf("Starting up vio server\n");
            _vmm->registry()->register_irq_obj(&_host_irq);
            _vmm->registry()->register_obj(this, _service_name);
          }
        break;
      case 0xf8: // l4virtio config cmd
        if (value == 0)
          {
            if (old_value & L4VIRTIO_CMD_MASK)
              {
                L4virtio::wmb();
                _kick_guest_irq->trigger();
              }

            _irq_sink.ack();
          }
        break;
      }
  }

  void kick()
  { _irq_sink.inject(); }

  long op_register_ds(L4virtio::Device::Rights,
                      L4::Ipc::Snd_fpage ds_cap_fp, l4_uint64_t ds_base,
                      l4_umword_t offset, l4_umword_t sz)
  {
    trace.printf("Registering dataspace from 0x%llx with %lu KiB, offset 0x%lx\n",
                 ds_base, sz >> 10, offset);

    if (!ds_cap_fp.cap_received())
      L4Re::chksys(-L4_EINVAL, "No dataspace cap received.");

    if (ds_base + sz > _drvmem_size)
      {
        warn.printf("Could not register device dataspace. Memory window size is 0x%llx, need 0x%llx\n",
                    _drvmem_size, ds_base + sz);
        return -L4_ERANGE;
      }

    // XXX Ds_handler should RAII the cap
    auto ds = L4Re::chkcap(L4::Epiface::server_iface()->rcv_cap<L4Re::Dataspace>(0));
    L4Re::chksys(L4::Epiface::server_iface()->realloc_rcv_cap(0));

    _vmm->add_mmio_device(Region::ss(_drvmem_base + ds_base, sz),
                          Vdev::make_device<Ds_handler>(ds, 0, sz, offset));

    return 0;
  }

  long op_register_iface(L4virtio::Device::Rights,
                         L4::Ipc::Snd_fpage irq_cap_fp,
                         L4::Ipc::Cap<L4::Triggerable> &host_irq,
                         L4::Ipc::Cap<L4Re::Dataspace> &config_ds)
  {
    if (!irq_cap_fp.cap_received())
      return -L4_EINVAL;

    _kick_guest_irq = L4Re::Util::Unique_cap<L4::Irq>(
        L4Re::chkcap(server_iface()->rcv_cap<L4::Irq>(0)));
    L4Re::chksys(server_iface()->realloc_rcv_cap(0));

    trace.printf("register client: host IRQ: %lx config DS: %lx\n",
                 _host_irq.obj_cap().cap(), mmio_ds().cap());

    host_irq = L4::Ipc::make_cap(_host_irq.obj_cap(), L4_CAP_FPAGE_RO);
    config_ds = L4::Ipc::make_cap(mmio_ds(), L4_CAP_FPAGE_RW);
    return 0;
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

private:
  L4Re::Util::Unique_cap<L4::Irq> _kick_guest_irq;
  Host_irq _host_irq;

  Vmm::Irq_sink _irq_sink;
  char _service_name[16];
  bool _ack_pending;

  l4_uint64_t _drvmem_base;
  l4_uint64_t _drvmem_size;
  Vmm::Guest *_vmm; // needed for registering DS handlers
};

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Vdev::Device_lookup const *devs,
                              Dt_node const &node)
  {
    int cap_name_len;
    char const *cap_name = node.get_prop<char>("l4vmm,virtiocap", &cap_name_len);
    if (!cap_name)
      {
        warn.printf("'l4vmm,virtiocap' property missing for virtio proxy device.\n");
        return nullptr;
      }

    cap_name_len = strnlen(cap_name, cap_name_len);

    auto cap = L4Re::Env::env()->get_cap<L4virtio::Device>(cap_name, cap_name_len);
    if (!cap)
      {
        warn.printf("'l4vmm,virtiocap' property: capability %.*s is invalid.\n",
                    cap_name_len, cap_name);
        return nullptr;
      }

    l4_uint64_t cfg_addr;
    l4_uint64_t cfg_size;

    if (node.get_reg_val(0, &cfg_addr, &cfg_size) < 0)
      {
        warn.printf("Reg entry for config space not found.\n");
        return nullptr;
      }

    auto c = make_device<Virtio_device_proxy>(cap_name, cfg_size);

    // register as mmio device for config space
    devs->vmm()->register_mmio_device(c, node, 0);

    return c;
  }
};

static F f;
static Device_type t = { "virtio-dev,mmio", nullptr, &f };

}
