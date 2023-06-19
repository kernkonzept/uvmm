/*
 * Copyright (C) 2016-2017, 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

namespace Vmm {
  class Vm;
}

namespace Monitor {

class Guest_debugger
{
public:
  explicit Guest_debugger(Vmm::Vm *)
  {}
};

}
