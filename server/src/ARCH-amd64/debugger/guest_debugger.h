/*
 * Copyright (C) 2019, 2024 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
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
