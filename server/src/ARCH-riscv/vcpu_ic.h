/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <atomic>

#include <l4/re/util/object_registry>
#include <l4/sys/cxx/ipc_epiface>

#include "irq.h"
#include "vcpu_ptr.h"

namespace Gic {

/**
 * The Vcpu_ic class implements core local interrupt controller, which keeps
 * track of a vCPU’s pending interrupts and updates the vCPU state
 * accordingly.
 *
 * Vcpu_ic encapsulates the interrupt state of its vCPU, exposing thread-safe
 * methods to modify it. This is important because the case where uvmm modifies
 * the state from the local vCPU thread itself must be handled differently than
 * a modification from another vCPU thread, for example a vCPU sending an IPI
 * to another vCPU. In the first case the affected vCPU is currently executing
 * uvmm code inside the entry handler, so the Vcpu_ic can update the vCPU state
 * immediately. In the second case we do not know whether the affected vCPU is
 * currently executing guest or uvmm code, so instead we send an IRQ
 * notification to the target vCPU thread. Thereupon, the target vCPU enters
 * the uvmm entry handler and processes the updates for its Vcpu_ic in the
 * corresponding IRQ handling routine (Vcpu_ic::handle_irq()).
 */
class Vcpu_ic
: public L4::Irqep_t<Vcpu_ic>,
  public virtual Vdev::Dev_ref
{
public:
  Vcpu_ic(Vmm::Vcpu_ptr vcpu, L4Re::Util::Object_registry *registry);
  ~Vcpu_ic();

  void attach_cpu_thread(L4::Cap<L4::Thread> thread);
  void handle_irq();

  /**
   * Notify vCPU that a software interrupt is pending.
   */
  void notify_ipi(Vmm::Vcpu_ptr current_vcpu);

  /**
   * Notify vCPU that a timer interrupt is pending.
   */
  void notify_timer();

  /**
   * Notify vCPU that the external interrupt pending state has changed.
   */
  void notify_external(Vmm::Vcpu_ptr current_vcpu);

  /**
   * Updates the external interrupt pending state.
   */
  void set_external_pending(bool pending, Vmm::Vcpu_ptr current_vcpu);

  // Must only be called from the vCPU thread
  void set_ipi();
  void set_timer();
  void clear_timer();
  void update_external();

private:

  enum Interrupt : l4_uint32_t
  {
    Interrupt_ipi      = 1 << 0,
    Interrupt_timer    = 1 << 1,
    Interrupt_external = 1 << 2,
  };

  void notify(Interrupt interrupt);

  Vmm::Vcpu_ptr _vcpu;

  // The vCPU notification IRQ
  L4Re::Util::Unique_cap<L4::Irq> _cpu_irq;

  // Interrupt classes that have an update pending
  std::atomic<l4_uint32_t> _update_pending = 0;

  // Whether at least one external interrupt is pending.
  // Should be a bool, but RISC-V has only word sized atomic instructions.
  std::atomic<l4_uint32_t> _external_pending = 0;

  L4Re::Util::Object_registry *_registry;
};

}
