/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/sys/vm>
#include <l4/re/dataspace>
#include <l4/re/util/br_manager>
#include <l4/re/util/object_registry>
#include <l4/re/util/unique_cap>

#include "debug.h"
#include "ds_mmio_mapper.h"
#include "mem_types.h"
#include "ram_ds.h"
#include "vm_memmap.h"
#include "pm.h"
#include "consts.h"
#include "monitor/monitor.h"

#include <cstdio>
#include <cstdlib>

namespace Vmm {

class Generic_guest
{
public:
  enum
  {
    Shutdown = 0x0,
    Reboot = 0x66
  };

  Generic_guest();
  virtual ~Generic_guest() = default;

  void prepare_generic_platform(Vdev::Device_lookup *devs)
  { _pm = devs->pm(); }

  L4Re::Util::Object_registry *registry() { return &_registry; }

  void register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> const &dev,
                            Region_type type,
                            Vdev::Dt_node const &node, size_t index = 0);

  Vm_mem *memmap()
  { return &_memmap; }

  void L4_NORETURN halt_vm()
  {
    Err().printf("VM entered a fatal state. Halting.\n");

    _pm->free_inhibitors();

    if (!Monitor::cmd_control_enabled())
      exit(EXIT_FAILURE);

    for (;;)
      wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
  }

  void L4_NORETURN shutdown(int val)
  {
    _pm->shutdown(val == Reboot);
    exit(val);
  }

  void handle_ipc(l4_msgtag_t tag, l4_umword_t label, l4_utcb_t *utcb)
  {
    // IPIs between CPUs have IRQs with zero label and are currently
    // not handled by the registery. Return immediately on these IPCs.
    if ((label & ~3UL) == 0)
      return;

    l4_msgtag_t r = _registry.dispatch(tag, label, utcb);
    if (r.label() != -L4_ENOREPLY)
      l4_ipc_send(L4_INVALID_CAP | L4_SYSF_REPLY, utcb, r,
                  L4_IPC_SEND_TIMEOUT_0);
  }

  int handle_mmio(l4_addr_t pfa, Vcpu_ptr vcpu)
  {
    Vm_mem::const_iterator f = _memmap.find(Region(Guest_addr(pfa)));

    if (f != _memmap.end())
      return f->second->access(pfa, pfa - f->first.start.get(),
                               vcpu, _task.get(),
                               f->first.start.get(), f->first.end.get());

    return -L4_EFAULT;
  }

  /**
   * Iterate over memory map and map all regions into the guest if possible.
   *
   * This function iterates over all memory areas and invokes their map_eager()
   * method. Areas are then responsible for the actual mapping if there is one.
   * There are some areas which trap and emulate mmio accesses and might not
   * map anything or might only provide mappings for parts of the area they are
   * responsible for.
   */
  void map_eager()
  {
    for (auto it : _memmap)
      it.second->map_eager(_task.get(), it.first.start, it.first.end);
  }

  void wait_for_ipc(l4_utcb_t *utcb, l4_timeout_t to)
  {
    l4_umword_t src;
    _bm.setup_wait(utcb, L4::Ipc_svr::Reply_separate);
    l4_msgtag_t tag = l4_ipc_wait(utcb, &src, to);
    if (!tag.has_error())
      handle_ipc(tag, src, utcb);
  }

  void add_mmio_device(Region const &region,
                       cxx::Ref_ptr<Vmm::Mmio_device> const &dev)
  {
    _memmap.add_mmio_device(region, dev);
  }

  void remap_mmio_device(Region const &old_region, Guest_addr const &addr)
  {
    _memmap.remap_mmio_device(old_region, addr);
  }

  L4::Cap<L4::Vm> vm_task()
  { return _task.get(); }

protected:
  void process_pending_ipc(Vcpu_ptr vcpu, l4_utcb_t *utcb)
  {
    while (vcpu->sticky_flags & L4_VCPU_SF_IRQ_PENDING)
      wait_for_ipc(utcb, L4_IPC_BOTH_TIMEOUT_0);
  }

  static Dbg warn()
  { return Dbg(Dbg::Core, Dbg::Warn, "guest"); }

  static Dbg info()
  { return Dbg(Dbg::Core, Dbg::Info, "guest"); }

  static Dbg trace()
  { return Dbg(Dbg::Core, Dbg::Trace, "guest"); }

  L4Re::Util::Br_manager _bm;
  L4Re::Util::Object_registry _registry;
  Vm_mem _memmap;
  L4Re::Util::Unique_cap<L4::Vm> _task;
  cxx::Ref_ptr<Pm> _pm;
};

} // namespace
