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

struct Msi_distributor : virtual Vdev::Dev_ref
{
  virtual ~Msi_distributor() = default;

  /// Analyse the MSI message and send it to the specified local APIC.
  virtual void send(Vdev::Msi_msg message) const = 0;
};

} // namespace Gic
