/*
 * Copyright (C) 2015-2018, 2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <utility>

#include <l4/cxx/ipc_server>
#include <l4/cxx/ref_ptr>
#include <l4/sys/irq>

#include "device.h"
#include "device_tree.h"
#include "generic_vcpu_ptr.h"

namespace Gic {

/**
 * Interface for handlers of interrupt sources.
 *
 * This is the generic interface for notifications from the
 * interrupt controller to an interrupt-emitting device.
 */
struct Irq_src_handler
{
  /**
   * Guest has issued end-of-interrupt message.
   */
  virtual void eoi() {}

  /**
   * Hint that the target vCPU of an IRQ source has changed.
   *
   * Might be used by the IRQ source to change the interrupt affinity
   * accordingly.
   */
  virtual void irq_src_target(Vmm::Generic_vcpu_ptr) {}

protected:
  virtual ~Irq_src_handler() = default;
};

/**
 * Generic interrupt controller interface.
 */
struct Ic : public Vdev::Device
{
  virtual void set(unsigned irq) = 0;
  virtual void clear(unsigned irq) = 0;

  /**
   * Register an IRQ source for forwarding downstream events.
   *
   * Only one device source can be registered, throws a runtime
   * exception if the IRQ source is already bound
   *
   * \param irq Irq number to connect the listener to.
   * \param src Device source. If the IRQ is already bound it needs to
   *            be the same device source as the already registered one.
   *            Set to nullptr to unbind a registered handler.
   *
   * \note The caller is responsible to ensure that the IRQ source handler is
   *       unbound before it is destructed.
   */
  virtual void bind_irq_src_handler(unsigned irq, Irq_src_handler *src) = 0;

  /**
   * Get the IRQ source currently bound to irq
   *
   * \param irq Irq number
   * \return Irq source currently bound to irq
   */
  virtual Irq_src_handler *get_irq_src_handler(unsigned irq) const = 0;

  /**
   * Extract the interrupt id from a device tree property.
   *
   * \param prop       Pointer to the property containing the interrupt
   *                   description. This may also point into the middle
   *                   of a property list.
   * \param propsz     Remaining length of the property list.
   * \param[out] read  If read is not a nullptr, then it contains the number
   *                   of elements that have been read.
   *
   * \retval >=0  Interrupt number to use with the controller.
   * \retval <0   Error reading property.
   */
  virtual int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const = 0;

};

} // namespace

namespace Vmm {

/**
 * Generic interrupt line on an interrupt controller.
 *
 * The Irq_sink implements a line-triggered interrupt and
 * remembers it's current state. It will only notify the
 * interrupt controller when it's state changes, thus effectively
 * ignoring multiple inject() or ack().
 */
class Irq_sink
{
public:
  Irq_sink() : _ic(nullptr) {}

  Irq_sink(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq)
  : _irq(irq), _ic(ic)
  {}

  Irq_sink(Irq_sink const &) = delete;
  Irq_sink(Irq_sink &&other) = delete;

  ~Irq_sink()
  { ack(); }

  void rebind(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq)
  {
    ack();

    _ic = ic;
    _irq = irq;
  }

  void inject()
  {
    if (_state || !_ic)
      return;

    _state = true;
    _ic->set(_irq);
  }

  void ack()
  {
    if (!_state || !_ic)
      return;

    _ic->clear(_irq);
    _state = false;
  }

  /**
   * Set the given IRQ source handler at the connected IC.
   *
   * \param handler  Handler to set for IRQ source notification.
   *
   * The function is only a forwarder to Ic::bind_irq_src_handler(), the
   * handler must still be managed by the caller. In particular, the caller
   * must make sure that the handler is unbound before the Irq_sink
   * object is destructed.
   *
   * If no IC has been bound yet, the function does nothing.
   */
  void set_irq_src_handler(Gic::Irq_src_handler *handler) const
  {
    if (_ic)
      _ic->bind_irq_src_handler(_irq, handler);
  }

private:
  unsigned _irq = 0;
  cxx::Ref_ptr<Gic::Ic> _ic;
  bool _state = false;
};

/**
 * Generic interrupt line on an interrupt controller.
 *
 * The Irq_edge_sink implements an edge-triggered interrupt.
 * It notifies the interrupt controller on each inject.
 */
class Irq_edge_sink
{
public:
  Irq_edge_sink() = default;

  Irq_edge_sink(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq)
  : _irq(irq), _ic(ic)
  {}

  void rebind(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq)
  {
    _ic = ic;
    _irq = irq;
  }

  void inject()
  { _ic->set(_irq); }

private:
  unsigned _irq;
  cxx::Ref_ptr<Gic::Ic> _ic;
};



} // namespace
