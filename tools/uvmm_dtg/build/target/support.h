/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <string>

#include <l4/re/env>
#include <l4/re/dataspace>
#include <l4/sys/scheduler>

namespace Support
{
  inline uint64_t ds_size(const std::string &name)
  {
    auto ds = L4Re::Env::env()->get_cap<L4Re::Dataspace>(name.c_str());
    if (ds.is_valid())
      return ds->size();
    return 0;
  }

  inline uint32_t cpu_count()
  {
    auto sched = L4Re::Env::env()->scheduler();
    if (!sched.is_valid())
      return 0;
    l4_umword_t max = 0;
    auto cs = l4_sched_cpu_set(0, 0);
    if (sched->info(&max, &cs).has_error())
      return 0;
    return max;
  }
};
