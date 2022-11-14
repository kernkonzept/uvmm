/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include "const.h"

#include <l4/re/env>
#include <l4/sys/err.h>
#include <l4/re/error_helper>
#include <l4/re/util/unique_cap>
#include <l4/re/util/debug>
#include <l4/cxx/utils>
#include <l4/sys/factory>
#include <l4/re/namespace>

#include <string>

constexpr OutFormat Default_format = Bin;

namespace Writer
{
  void static out(const std::string &name, const void *addr, size_t size)
  {
    if (name == "--")
      std::cout.write((const char*)addr, size);
    else
      {
        auto *e = L4Re::Env::env();
        auto ds = e->get_cap<L4Re::Dataspace>(name.c_str());
        if (!ds.is_valid())
          throw Exception("Can't find '" + name + "' dataspace capability");

        if (ds->size() <= size)
          throw Exception("Dataspace '" + name + "' is too small for device tree. "
                          "Needs to be at least " + std::to_string(size) +
                          " bytes big");

        L4Re::Rm::Unique_region<void *> msg;
        L4Re::chksys(e->rm()->attach(&msg, size,
                                     L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW
                                     | L4Re::Rm::F::Cache_normal,
                                     L4::Ipc::make_cap_rw(ds)));

        memcpy(msg.get(), addr, size);
      }
  }
};
