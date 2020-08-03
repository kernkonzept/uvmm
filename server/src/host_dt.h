/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdlib>
#include <cstring>

#include <l4/l4virtio/virtqueue>

#include "device.h"
#include "mem_types.h"
#include "monitor/dt_cmd_handler.h"

namespace Vdev {

/**
 * uvmm-internal device tree.
 */
class Host_dt
: public Monitor::Dt_cmd_handler<Monitor::Enabled, Host_dt>
{
public:
  Host_dt() = default;

  // Copying isn't allowed
  Host_dt(Host_dt const &) = delete;
  Host_dt &operator=(Host_dt const &) = delete;

  // Move is allowed
  Host_dt(Host_dt &&other)
  {
    _fdt = other._fdt;
    other._fdt = nullptr;
  }

  Host_dt &operator=(Host_dt &&other)
  {
    _fdt = other._fdt;
    other._fdt = nullptr;
    return *this;
  }

  ~Host_dt()
  { delete(_fdt); }

  bool valid() const noexcept
  { return _fdt; }

  Device_tree get() const
  { return Device_tree(_fdt); }

  void add_source(char const *fname);

  /**
   * Set the command line parameter in the device tree.
   *
   * \param cmd_line  Command line to pass to the device tree.
   *
   * If the device tree is not set up or if the cmd_line is a null pointer,
   * then the function is a no-op.
   */
  void set_command_line(char const *cmd_line);

  /**
   * Remove unused entries and pack the device tree.
   *
   * \note Only packing is implemented at the moment.
   */
  void compact()
  { _fdt->pack(); }

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
    if (Monitor::cmd_control_enabled())
      {
        // Create a copy for the monitor
        Dtb::Fdt *new_fdt = new Dtb::Fdt(*_fdt);
        _fdt->move(target);
        _fdt = new_fdt;
      }
    else
        _fdt->move(target);
  }

private:
  Dtb::Fdt *_fdt = nullptr;
};

}
