/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "debugger/generic_guest_debugger.h"
#include "monitor/dbg_cmd_handler.h"

namespace Monitor {

class Guest_debugger
: public Generic_guest_debugger,
  public Dbg_cmd_handler<Enabled, Guest_debugger>
{
public:
  using Generic_guest_debugger::Generic_guest_debugger;
};

}
