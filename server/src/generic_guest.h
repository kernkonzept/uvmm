/*
 * Copyright (C) 2015-2022 Kernkonzept GmbH.
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
#include <l4/re/util/unique_cap>
#include <l4/re/video/goos>
#include <mutex>

#include "debug.h"
#include "ds_mmio_mapper.h"
#include "mem_types.h"
#include "ram_ds.h"
#include "vm_memmap.h"
#include "pm.h"
#include "consts.h"
#include "monitor/monitor.h"
#include "io_device.h"
#include "generic_cpu_dev.h"
#include "vcpu_obj_registry.h"

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

  enum class Fault_mode
  {
    Ignore,
    Halt,
    Inject,
  };

  enum { Has_io_space = false };

  Generic_guest();
  virtual ~Generic_guest() = default;

  /*
   * By default only Ignore and Halt are supported. If an architecture supports
   * Inject it must override this method.
   */
  static bool fault_mode_supported(Fault_mode mode)
  {
    return mode == Fault_mode::Ignore || mode == Fault_mode::Halt;
  }

  void set_fault_mode(Fault_mode mode) { _fault_mode = mode; }

  void set_dt_addr(l4_addr_t dt_addr) { _dt_addr = dt_addr; }
  l4_addr_t dt_addr() const { return _dt_addr; }

  void prepare_generic_platform(Vdev::Device_lookup *devs)
  { _pm = devs->pm(); }

  Vcpu_obj_registry *registry()
  { return Generic_cpu_dev::main_vcpu().get_ipc_registry(); }

  void register_mmio_device(cxx::Ref_ptr<Vmm::Mmio_device> const &dev,
                            Region_type type,
                            Vdev::Dt_node const &node, size_t index = 0);

  void register_io_device(cxx::Ref_ptr<Vmm::Io_device> const &,
                          Region_type, Vdev::Dt_node const &, size_t = 0) {}
  void add_io_device(Io_region const &, cxx::Ref_ptr<Io_device> const &) {}
  void del_io_device(Io_region const &) {}

  bool register_framebuffer(l4_uint64_t /*addr*/, l4_uint64_t /*size*/,
                            const L4Re::Video::View::Info &)
  { return true; }

  /**
   * Return MMIO map.
   *
   * Must only be used before the guest started to run or for debugging. Might
   * be manipulated concurrently from other vCPUs!
   */
  Vm_mem *memmap()
  { return &_memmap; }

  virtual void L4_NORETURN halt_vm(Vcpu_ptr current_vcpu)
  {
    Err().printf("VM entered a fatal state. Halting.\n");

    _pm->free_inhibitors();

    if (!Monitor::cmd_control_enabled())
      exit(EXIT_FAILURE);

    for (;;)
      current_vcpu.wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
  }

  virtual void L4_NORETURN shutdown(int val)
  {
    _pm->shutdown(val == Reboot);
    sync_all_other_cores_off();
    exit(val);
  }

  virtual void sync_all_other_cores_off() const {};

  int handle_mmio(l4_addr_t pfa, Vcpu_ptr vcpu)
  {
    int ret = -L4_EFAULT;

    {
      std::unique_lock<std::mutex> lock(_memmap_lock);
      Vm_mem::const_iterator f = _memmap.find(Region(Guest_addr(pfa)));

      if (f != _memmap.end())
        {
          Region region = f->first;
          cxx::Ref_ptr<Mmio_device> device = f->second;
          lock.unlock();

          ret = device->access(pfa, pfa - region.start.get(),
                               vcpu, _task.get(),
                               region.start.get(), region.end.get());
          if (ret >= 0)
            return ret;
        }
    }

    auto insn = vcpu.decode_mmio();
    warn().printf("Invalid %s 0x%lx, ip 0x%lx! %sing...\n",
                  vcpu.pf_write() ? "write to" : "read from",
                  pfa, vcpu->r.ip,
                  _fault_mode == Fault_mode::Ignore
                    ? "Ignor"
                    : (_fault_mode == Fault_mode::Inject ? "Inject" : "Halt"));

    switch (_fault_mode)
      {
      case Fault_mode::Ignore:
        if (insn.access == Vmm::Mem_access::Load)
          {
            insn.value = 0;
            vcpu.writeback_mmio(insn);
          }
        return Jump_instr;
      case Fault_mode::Inject:
        if (inject_abort(pfa, vcpu))
          return Retry;
        warn().printf("Abort inject failed! Halting VM...\n");
        /* FALLTHRU */
      case Fault_mode::Halt:
        break;
      }

    return ret;
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
    std::lock_guard<std::mutex> g(_memmap_lock);
    for (auto it : _memmap)
      it.second->map_eager(_task.get(), it.first.start, it.first.end);
  }

  void add_mmio_device(Region const &region,
                       cxx::Ref_ptr<Vmm::Mmio_device> const &dev)
  {
    std::lock_guard<std::mutex> g(_memmap_lock);
    _memmap.add_mmio_device(region, dev);
  }

  void del_mmio_device(Region const &region)
  {
    std::lock_guard<std::mutex> g(_memmap_lock);
    Vm_mem::const_iterator f = _memmap.find(region);
    assert(f != _memmap.end());
    if (f == _memmap.end())
      return;
    f->second->unmap_guest_range(_task.get(), region.start,
                                 region.end.get() - region.start.get() + 1U);
    _memmap.erase(f);
  }

  /**
   * Delete any device covered by the given region.
   */
  void del_mmio_devices(Region const &region)
  {
    std::lock_guard<std::mutex> g(_memmap_lock);

    auto range = _memmap.equal_range(region);
    auto it = range.first;
    while (it != range.second)
      {
        it->second->unmap_guest_range(_task.get(), it->first.start,
                                      it->first.end - it->first.start + 1U);
        it = _memmap.erase(it);
      }
  }

  L4::Cap<L4::Vm> vm_task()
  { return _task.get(); }

protected:
  static Dbg warn()
  { return Dbg(Dbg::Core, Dbg::Warn, "guest"); }

  static Dbg info()
  { return Dbg(Dbg::Core, Dbg::Info, "guest"); }

  static Dbg trace()
  { return Dbg(Dbg::Core, Dbg::Trace, "guest"); }

  virtual bool inject_abort(l4_addr_t /*pfa*/, Vcpu_ptr /*vcpu*/)
  { return false; }

  std::mutex _memmap_lock;
  Vm_mem _memmap;
  L4Re::Util::Unique_cap<L4::Vm> _task;
  cxx::Ref_ptr<Pm> _pm;
  Fault_mode _fault_mode = Fault_mode::Ignore;
  l4_addr_t _dt_addr = 0;
};

} // namespace
