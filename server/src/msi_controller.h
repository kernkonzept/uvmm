/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "pci_device.h"
#include "device.h"

namespace Gic {

struct Msix_controller : virtual Vdev::Dev_ref
{
  virtual ~Msix_controller() = default;

  /// Analyse the MSI-X message and send it to the specified local APIC.
  virtual void send(l4_uint64_t msix_addr, l4_uint64_t msix_data) const = 0;
};

} // namespace Gic
