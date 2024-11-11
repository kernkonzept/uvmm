/*
 * Copyright (C) 2016-2017, 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
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
