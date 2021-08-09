/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include "guest.h"

namespace Vmm {

bool Guest::fault_mode_supported(Fault_mode mode)
{
  return Generic_guest::fault_mode_supported(mode);
}

bool Guest::inject_abort(Vcpu_ptr, bool, l4_addr_t)
{
  return false;
}

bool Guest::inject_undef(Vcpu_ptr)
{
  return false;
}

}
