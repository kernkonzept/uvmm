/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/l4virtio/virtqueue>

#include "device.h"
#include "mem_types.h"

namespace Vdev {

/**
 * uvmm-internal device tree.
 */
class Host_dt
{
public:
  Host_dt() : _dtmem(nullptr) {}
  Host_dt(Host_dt const &) = delete;
  Host_dt &operator=(Host_dt const &) = delete;
  Host_dt &operator=(Host_dt &&) = default;

  Host_dt(Host_dt &&other)
  {
    if (_dtmem)
      free(_dtmem);

    _dtmem = other._dtmem;
    other._dtmem = nullptr;
  }

  ~Host_dt()
  {
    if (_dtmem)
      free(_dtmem);
  }

  bool valid() const noexcept
  { return _dtmem; }

  Device_tree get() const
  { return Device_tree(_dtmem); }

  void add_source(char const *fname);

  /**
   * Set the command line paramter in the device tree.
   *
   * \param cmd_line  Command line to pass to the device tree.
   *
   * If the device tree is not set up or if the cmd_line is a null pointer,
   * then the function is a no-op.
   */
  void set_command_line(char const *cmd_line) const;

  /**
   * Remove unused entries and pack the device tree.
   *
   * \note Only packing is implemented at the moment.
   */
  void compact() const
  { fdt_pack(_dtmem); }

  /**
   * Move the device tree to the given target address.
   *
   * \param target  Target address where to move the device tree.
   *
   * After the operation the device tree is invalid and the
   * corresponding memory freed.
   */
  void move(void *target)
  {
    fdt_move(_dtmem, target, get().size());

    free(_dtmem);
    _dtmem = nullptr;
  }

private:
  void *_dtmem;
};

}
