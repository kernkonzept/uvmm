/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>

#include <map>

#include "io_device.h"
#include "vm_io_mem_cmd_handler.h"
#include "mem_types.h"

namespace Vmm {

class Io_mem
: public std::map<Io_region, cxx::Ref_ptr<Io_device>>,
  public Monitor::Io_mem_cmd_handler<Monitor::Enabled, Io_mem>
{};

} // namespace
