/*
 * Copyright (C) 2018-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>

#include "debug.h"
#include "device.h"
#include "device_factory.h"
#include "irq.h"

namespace Vdev {

/**
 * Helper class to allow iterating over the interrupts of a device tree node.
 */
class Irq_dt_iterator
{
public:
  /**
   * Create a new iterator.
   *
   * \param devs  Device repository of virtual uvmm devices.
   * \param node  Node to do the interrupt lookup for.
   *
   * The iterator is able to parse either class 'interrupt' properties or
   * the newer 'extended-interrupt' descriptors transparently. It finds and
   * creates interrupt parents as required while iterating over the interrupts.
   *
   * The iterator is set up to point before the first interrupt. You need to
   * call next() to advance the first interrupt. If there are any errors during
   * creation, for example when the node has no interrupt description at all,
   * then the first call to next() will fail.
   */
  Irq_dt_iterator(Device_lookup *devs, Dt_node const &node)
  : _node(node), _irq_num(0), _prop(nullptr)
  {
    if (node.has_prop("interrupts-extended"))
      {
        _is_extended = true;
        _prop = node.get_prop<fdt32_t>("interrupts-extended", &_prop_size);
      }
    else if (node.has_prop("interrupts"))
      {
        _is_extended = false;
        _ic_node = node.find_irq_parent();

        if (_ic_node.is_valid())
          {
            Device_lookup::Ic_error res = devs->get_or_create_ic(node, &_ic);

            if (res == Device_lookup::Ic_ok || res == Device_lookup::Ic_e_no_virtic)
              _prop = node.get_prop<fdt32_t>("interrupts", &_prop_size);
          }
      }
  }

  /**
   * Advance to the next interrupt entry.
   *
   * \param devs  Device repository of virtual uvmm devices.
   *
   * \retval L4_EOK      Successfully advanced to next interrupt.
   * \retval -L4_ERANGE  No further interrupts in the list.
   * \retval -L4_EINVAL  The device tree entry was badly formatted.
   * \retval -L4_ENODEV  The interrupt parent for the next interrupt is not
   *                     available.
   *
   * This function has to be called before reading any interrupt information,
   * including the first interrupt in the list.
   *
   * The state of the iterator is undefined after next() has returned
   * an error.
   */
  int next(Device_lookup *devs)
  {
    if (!_prop)
      {
        if (_node.has_irqs())
          warn().printf("Interrupt parent not found.\n");
        else
          warn().printf("Node has no interrupt information.\n");
        return -L4_EINVAL;
      }

    if (_prop_size <= 0)
      return -L4_ERANGE;

    if (_is_extended)
      next_extended_ic(devs);

    int cell_size;
    if (_ic)
      {
        _irq_num = _ic->dt_get_interrupt(_prop, _prop_size, &cell_size);

        if (_irq_num < 0)
          {
            warn().printf("Cannot translate interrupt.\n");
            return -L4_EINVAL;
          }
      }
    else
      {
        // unmanaged interrupt controller, get cell size for advancing only
        int sz;
        auto *cells = _ic_node.get_prop<fdt32_t>("#interrupt-cells", &sz);
        if (!cells)
          {
            warn().printf("#interrupt-cells property missing in interrupt parent '%s'.\n",
                _ic_node.get_name());
            return -L4_ENODEV;
          }
        if (sz != 1)
          {
            warn().printf("Bad #interrupt-cells property in interrupt parent '%s'.\n",
                _ic_node.get_name());
            return -L4_EINVAL;
          }

        cell_size = fdt32_to_cpu(*cells);

        if (_prop_size < cell_size)
          {
            warn().printf("Not enough parameters in interrupt description.\n");
            return -L4_EINVAL;
          }
      }

    _prop += cell_size;
    _prop_size -= cell_size;

    return L4_EOK;
  }

  /**
   * Check if there are more interrupts defined for the node.
   */
  bool has_next() const noexcept
  { return _prop_size > 0; }

  /**
   * Return the device of the virtual interrupt parent responsible for
   * handling the interrupt the iterator currently points to.
   *
   * \return Reference to the interrupt parent or nullptr if the interrupt
   *         parent is not managed by uvmm.
   */
  cxx::Ref_ptr<Gic::Ic> ic() const noexcept
  { return _ic; }

  /**
   * Check if the interrupt is handled by a virtual interrupt handler
   * that is managed by uvmm.
   */
  bool ic_is_virt() const noexcept
  { return bool(_ic); }

  /**
   * Return the interrupt number of the interrupt the iterator currently points
   * to.
   *
   * \return Interrupt number to use with the interrupt parent.
   *
   * \pre Must only be called when the interrupt parent is managed by uvmm
   *      (i.e. when ic() is not null).
   */
  unsigned irq() const
  {
    assert(_irq_num >= 0);
    return _irq_num;
  }

private:
  int next_extended_ic(Device_lookup *devs)
  {
    _ic_node = _node.find_phandle(*_prop);

    ++_prop;
    --_prop_size;

    if (!_ic_node.is_valid())
      {
        warn().printf("Interrupt parent node not found.\n");
        return -L4_EINVAL;
      }

    if (!_ic_node.is_enabled())
      {
        warn().printf("Interrupt parent '%s' disabled.\n", _ic_node.get_name());
        return -L4_ENODEV;
      }

    if (Vdev::Factory::is_vdev(_ic_node))
      {
        _ic = cxx::dynamic_pointer_cast<Gic::Ic>(
                Vdev::Factory::create_dev(devs, _ic_node));
        if (!_ic)
          {
            warn().printf("Virtual interrupt parent '%s' cannot be created.\n",
                          _ic_node.get_name());
            return -L4_ENODEV; // no device or not an IC
          }
      }
    else
      _ic = nullptr;

    return L4_EOK;
  }


  Dbg warn() const
  { return Dbg(Dbg::Core, Dbg::Warn, _node.get_name()); }

  /// Node that is currently being parsed.
  Dt_node _node;
  /// Interrupt parent device, if available.
  cxx::Ref_ptr<Gic::Ic> _ic;
  /// Node of interrupt parent device.
  Dt_node _ic_node;
  /// Interrupt number (only valid when _ic != nullptr).
  int _irq_num;
  /// Pointer to current position in interrupt property list.
  fdt32_t const *_prop;
  /// Remaining length of property list.
  int _prop_size;
  /// True if the property list being parsed is an extended list.
  bool _is_extended;
};

} // namespace
