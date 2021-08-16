/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
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
