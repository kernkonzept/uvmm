/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/l4virtio/virtqueue>

#include "device.h" // TODO typedef Device_tree instead?
#include "device_tree.h"

namespace Vmm {
    class Vm_ram;
    class Ram_free_list;
}

namespace Vdev {

/**
 * uvmm-internal device tree.
 */
class Host_dt
{
public:
  virtual ~Host_dt()
  {
    if (_dtmem)
      free(_dtmem);
  }

  bool valid() const noexcept
  { return _dtmem; }

  Device_tree get() const
  { return Device_tree(_dtmem); }

  void add_source(char const *fname);
  L4virtio::Ptr<void> pack_and_move(Vmm::Vm_ram *ram, Vmm::Ram_free_list *free_list);

private:
  void *_dtmem = nullptr;
};

}
