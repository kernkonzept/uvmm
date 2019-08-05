/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cstring>
#include <type_traits>

#include <l4/sys/err.h>

#include "debug.h"

namespace {

char const *const components[] =
  { "guest", "core", "cpu", "mmio", "irq", "dev", "pm", "vbus_event" };

bool verbosity_mask_from_string(char const *str, unsigned *mask)
{
  if (strcmp("quiet", str) == 0)
    *mask = Dbg::Quiet;
  else if (strcmp("warn", str) == 0)
    *mask = Dbg::Warn;
  else if (strcmp("info", str) == 0)
    *mask = Dbg::Warn | Dbg::Info;
  else if (strcmp("trace", str) == 0)
    *mask = Dbg::Warn | Dbg::Info | Dbg::Trace;
  else
    return false;

  return true;
}

} // namespace

int Dbg::set_verbosity(char const *str)
{
  unsigned mask = 0;
  if (verbosity_mask_from_string(str, &mask))
    {
      set_verbosity(mask);
      return L4_EOK;
    }

  static_assert(std::extent<decltype(components)>::value == Max_component,
                "Component names must match 'enum Component'.");

  for (unsigned i = 0; i < Max_component; ++i)
    {
      auto len = strlen(components[i]);
      if (strncmp(components[i], str, len) == 0 && str[len] == '='
          && verbosity_mask_from_string(str + len + 1, &mask))
        {
          set_verbosity(i, mask);
          return L4_EOK;
        }
    }

  return -L4_EINVAL;
}
