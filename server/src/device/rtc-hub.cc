/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include "rtc-hub.h"
Vdev::L4rtc_adapter *Vdev::L4rtc_hub::_adapter = nullptr;
l4_uint64_t Vdev::L4rtc_hub::_offset = 0;
