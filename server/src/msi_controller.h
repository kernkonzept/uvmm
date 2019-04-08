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

struct Msi_controller : virtual Vdev::Dev_ref
{
  virtual ~Msi_controller() = default;

  /// Analyse the MSI message and send it to the specified local APIC.
  virtual void send(l4_uint64_t msi_addr, l4_uint32_t msi_data) const = 0;
};

} // namespace Gic
