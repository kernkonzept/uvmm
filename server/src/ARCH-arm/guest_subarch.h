/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#pragma once

namespace Vmm {

enum { Guest_64bit_supported = false };

#define guest_msr_access guest_unknown_fault

}
