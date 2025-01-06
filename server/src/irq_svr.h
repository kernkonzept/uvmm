/*
 * Copyright (C) 2016-2020, 2023-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <mutex>
#include <l4/cxx/ref_ptr>
#include <l4/re/error_helper>

#include "debug.h"
#include "vcpu_obj_registry.h"
#include "irq.h"
#include "vcpu_ptr.h"

namespace Vdev {

/**
 * Interrupt passthrough.
 *
 * Forwards L4Re interrupts to an Irq_sink.
 */
class Irq_svr
: public Gic::Irq_src_handler,
  public L4::Irqep_t<Irq_svr>,
  public cxx::Ref_obj
{
  /**
   * Irq receiver binding state.
   *
   * Until the guest enables the interrupt, it stays in the Init state. Upon
   * the first enable(), it is decided if the kernel supports direct IRQ
   * injection. If not, move to the final Ipc_bound state where all interrupts
   * are funnled through uvmm. Otherwise the state will alternate beween
   * Vcpu_enabled and Vcpu_disabled, depending on the guest state.
   *
   * If the platform does not support direct injection at all, we move directly
   * to the Ipc_bound state. The same is true if the interrupt must be unmasked
   * at the ICU because the kernel does not support such an Irq.
   *
   * Possible state transitions:
   *
   *   Init -> Ipc_bound | Vcpu_enabled
   *   Vcpu_enabled -> Vcpu_disabled
   *   Vcpu_disabled -> Vcpu_enabled
   */
  enum class State : l4_uint8_t
  {
    Init,           ///< Initial state. Not bound to vCPU thread yet.
    Ipc_bound,      ///< Bound as regular IPC receiver at vCPU thread.
    Vcpu_enabled,   ///< Bound for direct injection at vCPU.
    Vcpu_disabled,  ///< Use direct injection but temporarily disabled by guest.
  };

public:
  Irq_svr(Vcpu_obj_registry *registry, L4::Cap<L4::Icu> icu,
          unsigned irq, cxx::Ref_ptr<Gic::Ic> const &ic, unsigned dt_irq)
  : _ic(ic),
    _dt_irq(dt_irq),
    _irq_num(irq),
    _registry(registry),
    _cap(L4Re::Util::make_unique_cap<L4::Irq>())
  {
    if (ic->get_irq_src_handler(dt_irq))
      L4Re::throw_error(-L4_EEXIST, "Bind IRQ for Irq_svr object.");

    L4Re::chkcap(_cap.get(), "Coult not alloc Irq_svr L4::Irq");
    L4Re::chksys(L4Re::Env::env()->factory()->create(_cap.get()),
                 "Failed to create Irq_svr L4::Irq");

    int ret = L4Re::chksys(icu->bind(irq, _cap.get()),
                           "Cannot bind to IRQ");
    switch (ret)
      {
      case 0:
        Dbg(Dbg::Dev, Dbg::Info, "irq_svr")
          .printf("Irq 0x%x will be unmasked directly\n", irq);
        set_eoi(_cap.get());
        // The _cap is not registered yet. If the platform supports it, we'll
        // try to setup direct vCPU vIRQ injection on the first enable(). If
        // that doesn't work, fall back to regular IPC.
        if (!bind_vcpu_supported())
          bind_as_ipc();
        break;
      case 1:
        Dbg(Dbg::Dev, Dbg::Info, "irq_svr")
          .printf("Irq 0x%x will be unmasked at ICU\n", irq);
        set_eoi(icu);
        // Fiasco direct injection does not work if the interrupt must be
        // unmasked at the ICU. Register as IPC receiver...
        bind_as_ipc();
        break;
      default:
        L4Re::throw_error(-L4_EINVAL, "Invalid return code from bind to IRQ");
        break;
      }

    ic->bind_irq_src_handler(dt_irq, this);
  }

  ~Irq_svr() noexcept
  {
    unbind_irq_src_handler();

    switch (_state)
      {
      case State::Ipc_bound:
        unbind_from_ipc();
        break;
      case State::Vcpu_enabled:
        unbind_from_vcpu();
        break;
      default:
        break;
      }
  }

  void handle_irq()
  { _ic->set(_dt_irq); }

  void eoi() override
  {
    // Opportunistic check for interrupts that are bound as IPC and are always
    // funnled through uvmm. We don't need the lock because State::Ipc_bound
    // is a final state.
    if (!bind_vcpu_supported() || _state == State::Ipc_bound)
      {
        _eoi->unmask(_irq_num);
        return;
      }

    std::lock_guard<std::mutex> lock(_mutex);

    switch (_state)
      {
      case State::Init:
        // EOI before IRQ was enabled -> ignore.
        break;
      case State::Ipc_bound:
        _eoi->unmask(_irq_num);
        break;
      case State::Vcpu_enabled:
        // This might happen if the guest moved an active IRQ between vCPUs.
        // The EOI is handled by uvmm and we can now re-bind the interrupt to
        // the vCPU.
        L4Re::chksys(_cap->bind_vcpu(_registry->server(), _vcpu_irq_cfg));
        _eoi->unmask(_irq_num);
        _active = false;
        break;
      case State::Vcpu_disabled:
        // This might happen if the guest disabled an active IRQ. Otherwise
        // the EOI is handled by the kernel directly.
        _active = false;
        break;
      }
  }

  void irq_src_target(Vmm::Generic_vcpu_ptr vcpu) override
  {
    std::lock_guard<std::mutex> lock(_mutex);

    _registry = vcpu.get_ipc_registry();
    switch (_state)
      {
      case State::Ipc_bound:
        L4Re::chkcap(_registry->move_obj(this), "move registry");
        break;
      case State::Vcpu_enabled:
        try_bind_as_vcpu();
        break;
      case State::Init:
      case State::Vcpu_disabled:
        break;
      }
  }

  void configure(l4_umword_t cfg) override
  {
    if (!bind_vcpu_supported())
      return;

    std::lock_guard<std::mutex> lock(_mutex);

    _vcpu_irq_cfg = cfg;
    if (_state == State::Vcpu_enabled)
      try_bind_as_vcpu();
  }

  bool enable() override
  {
    if (!bind_vcpu_supported())
      return false;

    std::lock_guard<std::mutex> lock(_mutex);

    switch (_state)
      {
      case State::Init:
        if (try_bind_as_vcpu())
          _state = State::Vcpu_enabled;
        else
          // Not implemented. Stick to the usual injection through uvmm.
          bind_as_ipc();
        _eoi->unmask(_irq_num);
        break;
      case State::Vcpu_disabled:
        try_bind_as_vcpu();
        _state = State::Vcpu_enabled;
        _eoi->unmask(_irq_num);
        break;
      case State::Ipc_bound:
      case State::Vcpu_enabled:
        break;
      }

    return _state == State::Vcpu_enabled;
  }

  void disable() override
  {
    if (!bind_vcpu_supported())
      return;

    std::lock_guard<std::mutex> lock(_mutex);

    // Only unbind if the IRQ was bound to the vCPU. Otherwise we need to keep
    // it permanently bound as IPC.
    if (_state == State::Vcpu_enabled)
      {
        unbind_from_vcpu();
        _state = State::Vcpu_disabled;
      }
  }

private:
  void set_eoi(L4::Cap<L4::Irq_eoi> eoi)
  { _eoi = eoi; }

  void unbind_irq_src_handler() const
  { _ic->bind_irq_src_handler(_dt_irq, nullptr); }

  void bind_as_ipc()
  {
    L4Re::chkcap(_registry->register_obj(this, _cap.get()),
                 "Cannot register irq");
    _state = State::Ipc_bound;
  }

  void unbind_from_ipc()
  {
    _registry->unregister_obj(this);
  }

#ifdef CONFIG_UVMM_IRQ_DIRECT_INJECT
  static constexpr bool bind_vcpu_supported()
  { return true; }

  bool try_bind_as_vcpu()
  {
    // The Irq was disabled or moved while being active. We first have to wait
    // for the EOI of the guest until it can be rebound...
    if (_active)
      return true;

    // (Re-)Bind as vCPU IRQ.
    int err;
    do
      {
        err = l4_error(_cap->bind_vcpu(_registry->server(), _vcpu_irq_cfg));
        if (err == -L4_EBUSY)
          {
            // The guest tried to move an vIRQ to a different vCPU while it was
            // active. We have to detach and wait for the EOI of the guest to
            // attach it then to the right vCPU.
            unbind_from_vcpu();
            if (_active)
              break;

            // The vIRQ was not active any more once we detached it. This might
            // happen if the vIRQ is routed to a different vCPU than the one
            // that reconfigures it. Try again...
          }
        else if (err != -L4_ENOSYS)
          L4Re::chksys(err, "Irq_svr bind_vcpu failed");
      }
    while (err == -L4_EBUSY);

    return err != -L4_ENOSYS;
  }

  void unbind_from_vcpu()
  {
    assert(_state == State::Vcpu_enabled);

    if (_active)
      return;

    int err = L4Re::chksys(_cap->detach(), "Detach Irq failed");
    _active = err == 2;
  }
#else
  static constexpr bool bind_vcpu_supported()
  { return false; }

  bool try_bind_as_vcpu()
  { return false; }

  void unbind_from_vcpu()
  {}
#endif

  cxx::Ref_ptr<Gic::Ic> _ic;  ///< Virtual interrupt controller
  unsigned _dt_irq = 0;       ///< Line number on virtual interrupt controller
  State _state = State::Init;
  bool _active = false;       ///< True if active on a vCPU
  L4::Cap<L4::Irq_eoi> _eoi;  ///< L4 Interface for EOI

protected:
  unsigned _irq_num;          ///< Line number on L4 ICU

private:
  // The following members are not used in the hot paths...
  Vcpu_obj_registry *_registry; ///< Registry of the vCPU the IRQ currently targets.
  l4_umword_t _vcpu_irq_cfg = 0;
  L4Re::Util::Unique_cap<L4::Irq> _cap;
  std::mutex _mutex;
};

} // namespace
