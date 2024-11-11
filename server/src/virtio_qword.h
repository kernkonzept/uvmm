/*
 * Copyright (C) 2016-2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

namespace Virtio {

union Qword
{
  l4_uint32_t w[2];
  l4_uint64_t q;
};

} // namespace Virtio
