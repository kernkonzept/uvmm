/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/icu>

#include "device.h"

namespace Vdev { namespace Msi {

/// Interface for access to the MSI allocator and the ICU providing the MSIs.
class Allocator : public virtual Vdev::Dev_ref
{
public:
  virtual ~Allocator() = 0;

  /// Access to the ICU providing the MSIs.
  virtual L4::Cap<L4::Icu> icu() const = 0;

  /**
   * Allocate a MSI vector with the app global MSI allocator.
   *
   * \retval >= 0        MSI number at the ICU.
   * \retval -L4_ENOMEM  Currently, no MSI is available.
   */
  virtual long alloc_msi() = 0;

  /// Free a previously allocated MSI vector.
  virtual void free_msi(unsigned num) = 0;

  /// Maximum number of MSIs at the ICU.
  virtual unsigned max_msis() const = 0;
};

inline Allocator::~Allocator() = default;

} } // namespace Vdev::Msi
