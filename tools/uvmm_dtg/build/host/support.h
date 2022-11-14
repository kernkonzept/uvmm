/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <string>

namespace Support
{
  inline uint64_t ds_size(const std::string &)
  { return 0; }

  inline uint64_t cpu_count()
  { return 0; }
};
