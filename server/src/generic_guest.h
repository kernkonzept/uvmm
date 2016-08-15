/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/re/dataspace>
#include <l4/re/util/br_manager>
#include <l4/re/util/object_registry>
#include <l4/sys/cache.h>
#include <l4/l4virtio/l4virtio>

#include "debug.h"
#include "device_tree.h"
#include "ds_mmio_mapper.h"
#include "irq.h"
#include "ram_ds.h"
#include "vm_memmap.h"
#include "vcpu.h"

#include <cstdio>

namespace Vmm {

class Generic_guest
{
public:
  explicit Generic_guest(L4::Cap<L4Re::Dataspace> ram,
                         l4_addr_t vm_base, l4_addr_t boot_offset = 0);

  virtual ~Generic_guest() = default;

  Cpu create_cpu();

  Vdev::Device_tree device_tree() const
  { return Vdev::Device_tree(_ram.access(_device_tree)); }

  bool has_device_tree() const
  { return _device_tree.is_valid(); }

  Ram_ds &ram()
  { return _ram; }

  virtual void show_state_registers(FILE *f) = 0;
  virtual void show_state_interrupts(FILE *f) = 0;

  L4Re::Util::Object_registry *registry() { return &_registry; }

  void set_fallback_mmio_ds(L4::Cap<L4Re::Dataspace> ds)
  { _mmio_fallback = ds; }

  void register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> &&dev,
                            Vdev::Dt_node const &node, int index = 0);

  L4virtio::Ptr<void> load_ramdisk_at(char const *ram_disk,
                                      L4virtio::Ptr<void> addr,
                                      l4_size_t *size);

  void cleanup_ram_state()
  {
    // XXX Some of the RAM memory might have been unmapped during copy_in()
    // of the binary and the RAM disk. The VM paging code, however, expects
    // the entire RAM to be present. Touch the RAM region again, now that
    // setup has finished to remap the missing parts.
    l4_touch_rw((void *)_ram.local_start(), _ram.size());

    if (has_device_tree())
      {
        l4_addr_t ds_start =
          reinterpret_cast<l4_addr_t>(_ram.access(_device_tree));
        l4_addr_t ds_end = ds_start + device_tree().size();
        l4_cache_clean_data(ds_start, ds_end);
        Dbg().printf("Cleaning caches [%lx-%lx] ([%lx+%llx])\n",
                     ds_start, ds_end, _ram.local_start(),
                     _device_tree.get());
      }
  }

  L4virtio::Ptr<void> load_device_tree_at(char const *src,
                                          L4virtio::Ptr<void> addr,
                                          l4_size_t padding);
  // architecture specific device tree manipulation hook
  void update_device_tree(char const *cmd_line);
  void set_ramdisk_params(L4virtio::Ptr<void> addr, l4_size_t size);

protected:
  /**
   * Load the binary with the given name.
   *
   * \param kernel      File name of the binary to load. May point to an
   *                    ELF file or a simple binary blob.
   * \param offset      For binary blobs, start address where to put the
   *                    binary.
   * \param entry[out]  Returns entry address as given in ELF header.
   *                    Unchanged for binary blobs.
   *
   * \return  Highest guest physical address used by binary.
   *          (Note that for ELF binaries there may be unused sections
   *           between start and end.)
   *
   * If the binary is an ELF binary it will be loaded to the address
   * stated in the program headers. Otherwise the binary blob will
   * be copied to the address given in start.
   *
   * This function also checks that the binary fits into available
   * ram, does not overlap with the device tree and synchronises
   * the Icaches.
   */
  L4virtio::Ptr<void> load_binary_at(char const *kernel, l4_addr_t offset,
                                     l4_addr_t *entry);

  void handle_ipc(l4_msgtag_t tag, l4_umword_t label, l4_utcb_t *utcb)
  {
    l4_msgtag_t r = _registry.dispatch(tag, label, utcb);
    if (r.label() != -L4_ENOREPLY)
      l4_ipc_send(L4_INVALID_CAP | L4_SYSF_REPLY, utcb, r,
                  L4_IPC_SEND_TIMEOUT_0);
  }

  void process_pending_ipc(Cpu vcpu, l4_utcb_t *utcb)
  {
    while (vcpu->sticky_flags & L4_VCPU_SF_IRQ_PENDING)
      {
        l4_umword_t src;
        _bm.setup_wait(utcb, L4::Ipc_svr::Reply_separate);
        l4_msgtag_t res = l4_ipc_wait(utcb, &src, L4_IPC_BOTH_TIMEOUT_0);
        if (!res.has_error())
          handle_ipc(res, src, utcb);
      }
  }

  bool handle_mmio(l4_addr_t pfa, Cpu vcpu)
  {
    Vm_mem::const_iterator f = _memmap.find(pfa);

    if (f != _memmap.end())
      return f->second->access(pfa, pfa - f->first.start,
                               vcpu, _task.get(),
                               f->first.start, f->first.end);

    if (!_mmio_fallback)
       return false;

    // Use the MMIO fallback dataspace to serve a 1:1 mapping.
    // This is necessary in some cases when guest use hardcoded
    // addresses to access devices instead of respecting
    // settings from the device tree.
    long res;
#if MAP_OTHER
    res = _mmio_fallback->map(pfa, L4Re::Dataspace::Map_rw, pfa,
                              l4_trunc_page(pfa), l4_round_page(pfa + 1),
                              _task.get());
#else
    l4_addr_t local_addr = 0;
    auto *e = L4Re::Env::env();
    res = e->rm()->reserve_area(&local_addr, L4_PAGESIZE,
                                L4Re::Rm::Search_addr);
    if (res < 0)
      {
        Err().printf("VM memory fallback: VM allocation failure)\n");
        return false;
      }

    res = _mmio_fallback->map(pfa, L4Re::Dataspace::Map_rw, local_addr,
                              l4_trunc_page(local_addr),
                              l4_round_page(local_addr + 1));
    if (res < 0)
      {
        Err().printf("VM memory fallback: failure mapping into VMM\n");
        return false;
      }

    res = l4_error(_task->map(e->task(),
                   l4_fpage(local_addr, L4_PAGESHIFT, L4_FPAGE_RW),
                   l4_trunc_page(pfa)));
#endif /* MAP_OTHER */

    if (res < 0)
      Err().printf("VM memory fallback: map to VM failure\n");

    return res >= 0;
  }

  void wait_for_ipc(l4_utcb_t *utcb, l4_timeout_t to)
  {
    l4_umword_t src;
    l4_msgtag_t tag = l4_ipc_wait(utcb, &src, to);
    if (!tag.has_error())
      handle_ipc(tag, src, utcb);
  }

  void __attribute__((noreturn)) halt_vm()
  {
    // XXX Only halts the current CPU. For the SMP case some
    // further signaling might be required.
    Err().printf("VM entered a fatal state. Halting.\n");
    for(;;)
      wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
  }

  L4Re::Util::Br_manager _bm;
  L4Re::Util::Object_registry _registry;
  Vm_mem _memmap;
  Ram_ds _ram;
  L4Re::Util::Auto_cap<L4::Task>::Cap _task;
  L4virtio::Ptr<void> _device_tree;

protected:
  enum { Nr_cpus = 1 };
  Cpu *_vcpu[Nr_cpus];
  L4::Cap<L4Re::Dataspace> _mmio_fallback;
};

} // namespace
