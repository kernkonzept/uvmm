/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "device.h"

struct Pci_bridge: Device
{
  using Device::Device;

  void add(Tree *dt) override;

  static unsigned next_dev_id() { return _dev_ids++; };

private:
  static unsigned _dev_ids;
};
