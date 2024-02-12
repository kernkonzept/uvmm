/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include <pthread.h>
#include <pthread-l4.h>

#include <l4/cxx/unique_ptr>
#include <l4/re/error_helper>
#include <l4/re/util/kumem_alloc>
#include <l4/re/util/br_manager>

#include <debug.h>
#include <device.h>
#include <vcpu_ptr.h>
#include <vcpu_obj_registry.h>

namespace Vmm {

class Generic_cpu_dev : public Vdev::Device
{
private:
  static Vcpu_ptr alloc_vcpu(unsigned idx)
  {
    l4_addr_t vcpu_addr;

    L4Re::chksys(L4Re::Util::kumem_alloc(&vcpu_addr, 0),
                 "kumem alloc for vCPU");

    Dbg(Dbg::Cpu, Dbg::Info).printf("Created VCPU %u @ %lx\n", idx, vcpu_addr);

    return Vcpu_ptr(reinterpret_cast<l4_vcpu_state_t *>(vcpu_addr));
  }

protected:
  /**
   * Stop execution of the vCPU device on IRQ event.
   */
  struct Stop_event
  {
    Stop_event(Generic_cpu_dev *c) : cpu(c) {}
    void act()
    { cpu->stop(); }

    void registration_failure()
    {
      Dbg().printf("Failed to register IRQ to stop vCPU; Shutdown "
                   "synchronization not enforcable.\n");
    }

    void trigger_failure(long ipc_err)
    {
      Dbg().printf("IPI to vCPU %u failed with error %li\n",
                   cpu->vcpu().get_vcpu_id(), ipc_err);
    }

    Generic_cpu_dev *cpu;
  };

protected:
  /**
   * Management wrapper for vCPU device specific actions to execute on IRQ event.
   *
   * \tparam EVENT  Action to execute when the IRQ is received.
   */
  template <typename EVENT>
  class Cpu_irq : public L4::Irqep_t<Cpu_irq<EVENT>>
  {
  public:
    Cpu_irq(EVENT const &a) : _event(a) {}

    void handle_irq() { _event.act(); }

    void arm(Vcpu_obj_registry *registry)
    {
      if (_irq.is_valid())
        {
          Dbg().printf("Rearming already armed CPU IRQ. Ignored.\n");
          return;
        }

      _irq = registry->register_irq_obj(this);
      if (!_irq.is_valid())
        _event.registration_failure();
    }

    void disarm(Vcpu_obj_registry *registry)
    {
      registry->unregister_obj(this);
      _irq.invalidate();
    }

    /**
     * \pre `_irq` capability is registered.
     */
    void trigger()
    {
      assert(_irq.is_valid());

      l4_msgtag_t tag = _irq->trigger();
      if (tag.has_error())
        _event.trigger_failure(l4_ipc_error(tag, l4_utcb()));
    }

    l4_msgtag_t receive(l4_timeout_t to = L4_IPC_NEVER)
    {
      return _irq->receive(to);
    }

  private:
    L4::Cap<L4::Irq> _irq;
    EVENT _event;
  };

public:
  Generic_cpu_dev(unsigned idx, unsigned phys_id)
  : _vcpu(nullptr), _phys_cpu_id(phys_id), _thread(nullptr),
    _registry(&_bm), _stop_irq(Stop_event(this))
  {
    // The CPU 0 (boot CPU) vCPU is allocated in main
    if (_main_vcpu_used || (idx != 0))
      _vcpu = alloc_vcpu(idx);
    else
      {
        _attached = true;
        _vcpu = _main_vcpu;
        _main_vcpu_used = true;
      }

    _vcpu.set_vcpu_id(idx);

    // entry_sp signals the state the CPU is in. When it starts for the very
    // first time, entry_sp is zero and needs to be initialised based on the
    // currently used stack. When the CPU is switched off and on again the
    // stack is re-used as is.
    _vcpu->entry_sp = 0;
  }

  virtual ~Generic_cpu_dev()
  { _stop_irq.disarm(_vcpu.get_ipc_registry()); }

  Vcpu_ptr vcpu() const
  { return _vcpu; }

  virtual void powerup_cpu();
  void reschedule();

  void send_stop_event()
  { _stop_irq.trigger(); }

  virtual void reset() = 0;
  virtual void stop() = 0;

  /**
   * Start CPU, run through reset and resume to the VM.
   */
  void startup();

  L4::Cap<L4::Thread> thread_cap() const
  { return Pthread::L4::cap(_thread); }

  static Vcpu_ptr main_vcpu() { return _main_vcpu; }

  static void alloc_main_vcpu()
  {
    if (*_main_vcpu)
      L4Re::throw_error(-L4_EEXIST, "cannot allocate mutiple main CPUs");

    _main_vcpu = alloc_vcpu(0);
    _main_vcpu.thread_attach();
    _main_vcpu.set_ipc_registry(&_main_registry);
    _main_vcpu.set_bm(&_main_bm);
  }

protected:
  Vcpu_ptr _vcpu;
  /// physical CPU to run on (offset into scheduling mask)
  unsigned _phys_cpu_id;
  pthread_t _thread;
  L4Re::Util::Br_manager _bm;
  Vcpu_obj_registry _registry;
  bool _attached = false;
  Cpu_irq<Stop_event> _stop_irq;

private:
  static Vcpu_ptr _main_vcpu;
  static L4Re::Util::Br_manager _main_bm;
  static Vcpu_obj_registry _main_registry;
  static bool _main_vcpu_used;
};


}
