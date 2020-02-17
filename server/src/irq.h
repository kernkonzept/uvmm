/*
 * Copyright (C) 2015 Kernkonzept GmbH.
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

namespace Gic {

/**
 * Interface for handlers of end-of-interrupt messages.
 *
 * This is the generic interface for notifications from the
 * interrupt controller to an interrupt-emitting device.
 */
struct Eoi_handler
{
  virtual void eoi() = 0;
protected:
  ~Eoi_handler() = default;
};

/**
 * Generic interrupt controller interface.
 */
struct Ic : public Vdev::Device
{
  virtual void set(unsigned irq) = 0;
  virtual void clear(unsigned irq) = 0;

  /**
   * Register a device source for forwarding downstream events.
   *
   * Only one device source can be registered, throws a runtime
   * exception if the irq source is already bound
   *
   * \param irq Irq number to connect the listener to.
   * \param src Device source. If the irq is already bound it needs to
   *            be the same device source as the already registered one.
   *            Set to nullptr to unbind a registered handler.
   *
   * \note The caller is responsible to ensure that the eoi handler is
   *       unbound before it is destructed.
   */
  virtual void bind_eoi_handler(unsigned irq, Eoi_handler *src) = 0;

  /**
   * Get the irq source currently bound to irq
   *
   * \param irq Irq number
   * \return Irq source currently bound to irq
   */
  virtual Eoi_handler *get_eoi_handler(unsigned irq) const = 0;

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
  Irq_sink() : _ic(nullptr), _state(false) {}

  Irq_sink(cxx::Ref_ptr<Gic::Ic> const &ic, unsigned irq)
  : _irq(irq), _ic(ic), _state(false)
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
   * Set the given end-of-interrupt handler at the connected IC.
   *
   * \param handler  Handler to set for EOI notification.
   *
   * The function is only a forwarder to Ic::bind_eoi_handler(), the
   * handler must still be managed by the caller. In particular, the caller
   * must make sure that the handler is unbound before the Irq_sink
   * object is destructed.
   *
   * If no IC has been bound yet, the function does nothing.
   */
  void set_eoi_handler(Gic::Eoi_handler *handler) const
  {
    if (_ic)
      _ic->bind_eoi_handler(_irq, handler);
  }

private:
  unsigned _irq;
  cxx::Ref_ptr<Gic::Ic> _ic;
  bool _state;
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
