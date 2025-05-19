/*
 * Copyright (C) 2017-2020, 2022-2024, 2023-2025 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <string.h>

#include <l4/re/util/cap_alloc>
#include <l4/re/dataspace>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/cxx/bitmap>

#include <l4/l4virtio/virtio.h>
#include <l4/l4virtio/server/virtio>
#include <l4/l4virtio/server/l4virtio>

#include "debug.h"
#include "virtio.h"
#include "irq_dt.h"
#include "mmio_device.h"
#include "virtio_device_mem_pool.h"

namespace Vdev {

/**
 * Abstract interfaces for irq management of an virtio device proxy controller.
 */
struct Virtio_device_proxy_irq_sender
{
  virtual void kick_irq(l4_uint32_t idx) = 0;
  virtual void ack_irq(l4_uint32_t /*idx*/) {}
};

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
class Virtio_device_proxy
: public Vdev::Device,
  public Vmm::Mmio_device_t<Virtio_device_proxy>,
  public L4::Epiface_t<Virtio_device_proxy, L4virtio::Device>
{
  enum
  {
    Config_ds_size = L4_PAGESIZE,
    Max_mem_regions = 8
  };

  struct Host_irq : public L4::Irqep_t<Host_irq>
  {
    explicit Host_irq(Virtio_device_proxy *s) : s(s) {}
    Virtio_device_proxy *s;
    void handle_irq() { s->irq_kick(); }
  };

  struct L4_region_config
  {
    // C type shared with guest
    struct Region_config_t
    {
      char name[16];
      l4_uint32_t num;
      struct
      {
        l4_uint64_t phys;
        l4_uint64_t size;
        l4_uint64_t base;
      } region[Max_mem_regions];
    };

    L4_region_config(l4_uint64_t size)
    {
      auto *e = L4Re::Env::env();
      L4Re::Util::Ref_cap<L4Re::Dataspace>::Cap ds
        = L4Re::chkcap(L4Re::Util::make_ref_cap<L4Re::Dataspace>(),
                       "Allocate Virtio::Dev dataspace capability.");

      L4Re::chksys(e->mem_alloc()->alloc(size, ds.get()),
                   "Allocate Virtio::Dev configuration memory.");

      ds_mgr = cxx::make_ref_obj<Vmm::Ds_manager>("Virtio_device_proxy: l4 cfg",
                                                  ds, 0, size,
                                                  L4Re::Rm::F::RW |
                                                  L4Re::Rm::F::Cache_uncached);
      ds_hdlr = Vdev::make_device<Ds_handler>(ds_mgr, L4_FPAGE_RO);

      get()->num = 0;
    }

    Region_config_t *get()
    { return ds_mgr->local_addr<Region_config_t*>(); }

    Region_config_t const *get() const
    { return ds_mgr->local_addr<Region_config_t*>(); }

    int add_region(Vmm::Region const *region, l4_uint64_t base)
    {
      if (!region)
        return -L4_EINVAL;

      auto config = get();
      if (config->num >= Max_mem_regions)
        return -L4_EINVAL;

      config->region[config->num].phys = region->start.get();
      config->region[config->num].size = region->size();
      config->region[config->num].base = base;
      ++(config->num);

      return L4_EOK;
    }

    l4_uint32_t count() const
    { return get()->num; }

    int region(l4_uint32_t i, l4_uint64_t *phys, l4_uint64_t *size) const
    {
      auto c = get();
      if (i >= c->num)
        return -L4_ERANGE;

      *phys = c->region[i].phys;
      *size = c->region[i].size;

      return L4_EOK;
    }

    cxx::Ref_ptr<Ds_handler> ds_hdlr;
    cxx::Ref_ptr<Vmm::Ds_manager> ds_mgr;
  };

public:
  Virtio_device_proxy(char const *name,
                      l4_uint32_t id,
                      Virtio_device_proxy_irq_sender *irq_sender,
                      L4Re::Util::Ref_cap<L4::Rcv_endpoint>::Cap cap,
                      Vmm::Guest *vmm,
                      cxx::Ref_ptr<Virtio_device_mem_pool> mempool)
  : _host_irq(this),
    _vmm(vmm),
    _l4cfg(L4_PAGESIZE),
    _mempool(mempool),
    _id(id),
    _irq_sender(irq_sender),
    _cap(cap)
  {
    char buf[18];
    snprintf(buf, sizeof(buf), "l4proxy %u", _id);
    l4_debugger_set_object_name(cap.cap(), buf);

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

    // Make sure the receive window of the main cpu server loop is large
    // enough. Other VMs may already wait in the kernel to connect to this vio
    // cap. We have to make sure the receive window has enough space for the
    // RAM cap before we ever call wait_for_ipc.
    Vmm::Generic_cpu_dev::main_vcpu().get_bm()->alloc_buffer_demand(
      get_buffer_demand());

    // Add name if available
    if (name)
      strncpy(_l4cfg.get()->name, name, sizeof(_l4cfg.get()->name) - 1);
  }

  virtual ~Virtio_device_proxy()
  {
    // We need to delete the IRQ/Gate object ourselves. Otherwise it will not
    // be unbind from the thread. Please note that specifying "unmap" in the
    // unregister call is not enough, because there the L4_FP_DELETE_OBJ flag
    // is missing.
    // TODO: unregister_obj calls modify_senders. This call makes only sense on
    // the thread where the IRQ/Gate is bound. However, Linux is free to remove
    // the "virtio device proxy" from any vpcu, meaning we could end up here on
    // a vcpu != obj bound vcpu. Therefore, we actually would need some
    // infrastructure to call unregister_obj from the correct vcpu!
    L4::Cap<L4::Task>(L4Re::This_task)->delete_obj(_host_irq.obj_cap());
    _vmm->registry()->unregister_obj(&_host_irq, false);
    L4::Cap<L4::Task>(L4Re::This_task)->delete_obj(obj_cap());
    _vmm->registry()->unregister_obj(this, false);
    for (l4_uint32_t i = 0; i < _l4cfg.count(); ++i)
      {
        l4_uint64_t phys, size;
        if (!_l4cfg.region(i, &phys, &size))
          _mempool->drop_region(phys, size);
      }
  }

  void map_eager(L4::Cap<L4::Vm>, Vmm::Guest_addr, Vmm::Guest_addr) override
  {} // nothing to map

  l4_uint64_t read(unsigned reg, char width, unsigned /*cpu_id*/)
  {
    if (L4_UNLIKELY(reg >= mmio_size()))
      return 0;

    // only naturally aligned 32bit accesses are allowed
    if (L4_UNLIKELY(reg & ((1UL << width) - 1)))
      return 0;

    // Right now all reads are allowed. The guest driver uses L4virtio specific
    // fields, so don't block them. This may change in the future.

    return Vmm::Mem_access::read_width(local_addr() + reg, width);
  }

  void write(unsigned reg, char width, l4_umword_t value, unsigned /*cpu_id*/)
  {
    if (L4_UNLIKELY(reg >= mmio_size()))
      return;

    // only naturally aligned 32bit accesses are allowed
    if (L4_UNLIKELY(reg & ((1UL << width) - 1)))
      return;

    // Note: do not try to optimize this. The order of commands for the
    // different regs is *very* important. E.g. sometimes the value itself
    // *must* be written before something else is done and sometimes it is the
    // other way around.
    switch (reg)
      {
      case Virtio::Hdr_off_magic:
        {
          if (virtio_cfg()->magic == L4VIRTIO_MAGIC)
            {
              warn.printf("Device reset via writing to virtio magic not "
                          "supported. Write ignored.\n");
              break;
            }

          // Write the new value to the virtio header
          virtio_cfg()->magic = value;
          if (value == L4VIRTIO_MAGIC)
            {
              trace.printf("Starting up vio server\n");
              auto irq =_vmm->registry()->register_irq_obj(&_host_irq);
              char buf[23];
              snprintf(buf, sizeof(buf), "l4proxy %u: irq", _id);
              l4_debugger_set_object_name(irq.cap(), buf);
              _vmm->registry()->register_obj(this, _cap.get());
            }

          break;
        }

      case Virtio::Hdr_off_queue_notify:
        {
          // Acknowledge earlier queue irqs
          irq_ack();
          // Now kick the driver
          virtio_cfg()->irq_status |= L4VIRTIO_IRQ_STATUS_VRING;
          _kick_guest_irq->trigger();
          // do not actually write the value
          break;
        }

      case Virtio::Hdr_off_cmd:
        {
          if (value == 0)
            {
              // Acknowledge earlier queue irqs
              // Make sure we do this *before* we actually write the value back
              // to memory. The other side may poll this value and submit a new
              // irq straight away, which may lead to an race and therefore
              // missed irqs.
              irq_ack();

              // if we transition from cmd -> ack, trigger a guest irq
              if (virtio_cfg()->cmd & L4VIRTIO_CMD_MASK)
                {
                  L4virtio::wmb();
                  virtio_cfg()->irq_status |= L4VIRTIO_IRQ_STATUS_VRING;
                  _kick_guest_irq->trigger();
                }
            }

          // Write the new value to the virtio header
          virtio_cfg()->cmd = value;
          break;
        }

      default:
        // Write the new value to the virtio header
        Vmm::Mem_access::write_width(local_addr() + reg, value, width);
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

    auto *region = _mempool->register_ds(ds, ds_base, offset, sz);
    if (!region)
      return -L4_ERANGE;

    return _l4cfg.add_region(region, ds_base);
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

  void irq_kick()
  { _irq_sender->kick_irq(_id); }

  void irq_ack()
  { _irq_sender->ack_irq(_id); }

  cxx::Ref_ptr<Vmm::Mmio_device> get_mmio_handler(unsigned i)
  {
    if (i == 0)
      return cxx::Ref_ptr<Vmm::Mmio_device>(this);
    else if (i == 1)
      return _l4cfg.ds_hdlr;

    return nullptr;
  }

protected:
  char const *dev_name() const override { return "Virtio_device_proxy_mmio"; }

  L4::Cap<L4Re::Dataspace> mmio_ds() const
  { return _cfg_ds.get(); }

  l4_size_t mmio_size() const
  { return Config_ds_size; }

  l4_addr_t local_addr() const
  { return reinterpret_cast<l4_addr_t>(_cfg_header.get()); }

  l4virtio_config_hdr_t *virtio_cfg() const
  { return _cfg_header.get(); }

  L4Re::Rm::Unique_region<l4virtio_config_hdr_t *> _cfg_header;
  L4Re::Util::Unique_del_cap<L4Re::Dataspace> _cfg_ds;

  L4Re::Util::Unique_cap<L4::Irq> _kick_guest_irq;
  Host_irq _host_irq;

  Vmm::Guest *_vmm; // needed for registering DS handlers
  L4_region_config _l4cfg;
  cxx::Ref_ptr<Virtio_device_mem_pool> _mempool;

  l4_uint32_t _id;
  Virtio_device_proxy_irq_sender *_irq_sender;
  L4Re::Util::Ref_cap<L4::Rcv_endpoint>::Cap _cap;

  Dbg trace = {Dbg::Dev, Dbg::Trace, "viodev"};
  Dbg warn = {Dbg::Dev, Dbg::Warn, "viodev"};
  Dbg info = {Dbg::Dev, Dbg::Info, "viodev"};
};

/**
 * Virtio proxy controller base class.
 *
 * This class can be used as base for the controller device on an actual bus.
 * It manages Virtio_device_proxy instances and forwards mmio access to the
 * actual devices.
 *
 * There are two mmio regions:
 *
 * 1. A control region of the virtio device proxy controller itself. This is
 *    used for dynamically adding/removing of virtio device proxies besides
 *    other things.
 *
 * 2. One big io memory range for all possible virtio device proxy child
 *    devices. Every virtio device proxy gets 2 pages, one for the virtio
 *    config page itself & one for a special L4 config page. They are
 *    continuous and can be simply accessed by the virtio device proxy ID (see
 *    Proxy_region_mapper). This looks like this:
 *
 *       -----------------
 *       | L4 Config     |
 * ID 0  -----------------
 *       | Virtio Config |
 *       -----------------
 *       -----------------
 *       | L4 Config     |
 * ID 1  -----------------
 *       | Virtio Config |
 *       -----------------
 * ...
 *
 * The actual content of both pages is managed by the Virtio_device_proxy
 * instances itself.
 */
class Virtio_device_proxy_control_base
: public Vmm::Mmio_device_t<Virtio_device_proxy_control_base>,
  public Virtio_device_proxy_irq_sender,
  public Vdev::Device
{
  enum
  {
    Add_reg = 0x0,
    Del_reg = 0x4,
    Count_reg = 0x8,
  };

  enum
  {
    Proxy_cfg_sub_size = L4_PAGESIZE,
    Proxy_cfg_size = Proxy_cfg_sub_size * 2
  };

  /**
   * Simple ID resource manager.
   *
   * Manages IDs with a bitmap for fast access.
   */
  struct Id_allocator
  {
    Id_allocator(l4_uint32_t bit_count)
    : _bits(std::make_unique<char[]>(
              cxx::Bitmap_base::bit_buffer_bytes(bit_count))),
      _bm(_bits.get()),
      _bit_count(bit_count)
    {
      memset(_bits.get(), 0, cxx::Bitmap_base::bit_buffer_bytes(_bit_count));
    }

    long get()
    {
      auto bit = _bm.scan_zero(_bit_count);
      if (bit == -1)
        return bit;

      _bm.set_bit(bit);

      return bit;
    }

    void put(long bit)
    { _bm.clear_bit(bit); }

    std::unique_ptr<char[]> _bits;
    cxx::Bitmap_base _bm;
    l4_uint32_t _bit_count;
  };

public:
  using viocaps_vector =
    std::vector<std::pair<char const*, L4Re::Util::Ref_cap<L4::Rcv_endpoint>::Cap>>;

  /**
   * This manages the region containing the two pages required per actual
   * virtio proxy device.
   *
   * The first page contains the L4 specific configuration. The second page is
   * the virtio config page.
   *
   * The virtio proxy device ID is the index into this region.
   */
  class Proxy_region_mapper : public Vmm::Mmio_device
  {
  public:
    Proxy_region_mapper(l4_uint32_t max)
    : _ida(max)
    {}

    int access(l4_addr_t pfa, l4_addr_t offset, Vmm::Vcpu_ptr vcpu,
               L4::Cap<L4::Vm> vm, l4_addr_t /*min*/, l4_addr_t /*max*/) override
    {
      auto id = offset_to_id(offset);
      auto sub = offset_to_sub(offset);

      cxx::Ref_ptr<Virtio_device_proxy> proxy = get_proxy(id);
      if (!proxy)
        return -L4_ENXIO;

      return
        proxy->get_mmio_handler(sub)->access(pfa,
                                             offset - offset_for_proxy(id, sub),
                                             vcpu, vm,
                                             l4_trunc_page(pfa),
                                             l4_trunc_page(pfa) + L4_PAGESIZE);
    }

    void map_eager(L4::Cap<L4::Vm>, Vmm::Guest_addr, Vmm::Guest_addr) override
    {}

    char const *dev_name() const override { return "Proxy_region_mapper"; };

    void set_mapping_addr(Vmm::Guest_addr addr)
    {
      assert(_addr == Vmm::Guest_addr(0));
      _addr = addr;
    }

    /**
     * Create a new virtio device proxy.
     *
     * \retval >=0 ID of the new Virtio device proxy.
     * \retval < 0 Maximum number of supported Virtio device proxies reached.
     */
    l4_uint32_t add(Virtio_device_proxy_irq_sender *irq_sender,
                    char const *name,
                    L4Re::Util::Ref_cap<L4::Rcv_endpoint>::Cap cap,
                    Vmm::Guest *vmm,
                    cxx::Ref_ptr<Virtio_device_mem_pool> mempool)
    {
      auto id = _ida.get();
      if (id < 0)
        return id;

      _devices.emplace(id,
                       cxx::make_ref_obj<Virtio_device_proxy>(name,
                                                              id,
                                                              irq_sender,
                                                              cap,
                                                              vmm,
                                                              mempool));
      return id;
    }

    /**
     * Deletes a virtio device proxy.
     *
     * Frees all associated resources and returns the ID into the pool.
     */
    void del(l4_uint32_t id)
    {
      auto p = _devices.find(id);
      if (p != _devices.end())
        {
          _devices.erase(p);
          _ida.put(id);
        }
    }

    cxx::Ref_ptr<Virtio_device_proxy> get_proxy(l4_uint32_t id)
    {
      auto p = _devices.find(id);
      if (p != _devices.end())
        return p->second;
      return nullptr;
    }

    static l4_size_t max_mem_size(l4_uint32_t max_entries)
    { return max_entries * Proxy_cfg_size; }

    l4_uint32_t count() const
    { return _devices.size(); }

private:
    static l4_uint32_t offset_to_id(l4_addr_t offset)
    { return offset / Proxy_cfg_size; }

    static l4_uint32_t offset_to_sub(l4_addr_t offset)
    { return (offset % Proxy_cfg_size) / Proxy_cfg_sub_size; }

    static l4_addr_t offset_for_proxy(l4_uint32_t id, l4_uint32_t sub)
    { return id * Proxy_cfg_size + sub * Proxy_cfg_sub_size; }

    Id_allocator _ida;
    std::map<l4_uint32_t, cxx::Ref_ptr<Virtio_device_proxy>> _devices;
    Vmm::Guest_addr _addr = Vmm::Guest_addr(0);
  };

  Virtio_device_proxy_control_base(l4_uint32_t max_devs,
                                   Vmm::Guest *vmm,
                                   cxx::Ref_ptr<Virtio_device_mem_pool> mempool,
                                   viocaps_vector const &viocaps)
  : _vmm(vmm),
    _mempool(mempool),
    _prm(cxx::make_ref_obj<Proxy_region_mapper>(max_devs))
  {
    // Add any static configured devices
    for (auto &c: viocaps)
      _prm->add(this, c.first, c.second, vmm, _mempool);
  }

  /**
   * Read access to the virtio device proxy controller mmio region.
   *
   * Add_reg: Reading from this triggers the addition of a new virtio device
   *          proxy to this virtio device proxy controller. On return to the
   *          guest, the read value is the id of the new device. On error -1 is
   *          returned.
   *
   * Count_reg: Reading this value returns the actual count of currently
   *            configured virtio device proxies. Note, that the ids are not
   *            necessarily continuous.
   *
   * All other reads are ignored and -1 is returned.
   */
  l4_uint32_t read(unsigned reg, char /*size*/, unsigned /*cpu_id*/)
  {
    switch (reg)
      {
      case Add_reg:
        {
          auto cap = L4Re::Util::make_ref_cap<L4::Rcv_endpoint>();
          if (!cap.is_valid())
            return -1;

          if (l4_error(L4Re::Env::env()->factory()->create_gate(
                       cap.get(), L4::Cap_base::Invalid, 0)) < 0)
            return -1;

          return _prm->add(this, nullptr, cap, _vmm, _mempool);
        }
      case Count_reg:
        return _prm->count();
      }

    warn().printf("Read from unsupported register %x.\n", reg);

    return -1;
  }

  /**
   * Write access to the virtio device proxy controller mmio region.
   *
   * Del_reg: Writing to this value triggers a deletion of the virtio device
   *          proxy with the written id.
   *
   * All other writes are ignored.
   */
  void write(unsigned reg, char /*size*/, l4_umword_t value, unsigned /*cpu_id*/)
  {
    switch (reg)
      {
        case Del_reg:
          _prm->del(value);
          break;
        default:
          warn().printf("Write to unsupported register %x.\n", reg);
      }
  }

  char const *dev_name() const override { return "Proxy_control"; }

protected:
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "proxy_ctl"); }

  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Virtio_device_mem_pool> _mempool;
  cxx::Ref_ptr<Proxy_region_mapper> _prm;
};

}
