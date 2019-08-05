/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cstdlib>
#include <cstring>
#include <type_traits>

#include <l4/sys/err.h>

#include "debug.h"

namespace {

struct Debug_level {
  char const *name;
  unsigned mask;
};

Debug_level const debug_levels[] = {
  { "quiet", Dbg::Quiet },
  { "warn", Dbg::Warn },
  { "info", Dbg::Warn | Dbg::Info },
  { "trace", Dbg::Warn | Dbg::Info | Dbg::Trace }
};

bool verbosity_mask_from_string(char const *str, unsigned *mask)
{
  for (auto const &debug_level : debug_levels)
    {
      if (strcmp(debug_level.name, str) == 0)
        {
          *mask = debug_level.mask;
          return true;
        }
    }

  return false;
}

bool verbosity_mask_to_string(unsigned mask, char const **str)
{
  for (auto const &debug_level : debug_levels)
    {
      if (debug_level.mask == mask)
        {
          *str = debug_level.name;
          return true;
        }
    }

  return false;
}

char const *const components[] =
  { "guest", "core", "cpu", "mmio", "irq", "dev", "pm", "vbus_event" };

bool component_from_string(char const *str, size_t len, unsigned *c)
{
  static_assert(std::extent<decltype(components)>::value == Dbg::Max_component,
                "Component names must match 'enum Component'.");

  for (unsigned i = 0; i < Dbg::Max_component; ++i)
    {
      if (len == strlen(components[i]) && memcmp(components[i], str, len) == 0)
        {
          *c = i;
          return true;
        }
    }

  return false;
}

} // namespace

int
Dbg::get_verbosity(unsigned c, char const **str)
{
  unsigned shift = Verbosity_shift * c;
  unsigned mask = (level & (Verbosity_mask << shift)) >> shift;

  if (!verbosity_mask_to_string(mask, str))
    return -L4_EINVAL;

  return L4_EOK;
}

int
Dbg::get_verbosity(char const *c, char const **str)
{
  unsigned cu;
  if (!component_from_string(c, strlen(c), &cu))
    return -L4_EINVAL;

  return get_verbosity(cu, str);
}

int
Dbg::set_verbosity(char const *str)
{
  unsigned mask = 0;
  if (verbosity_mask_from_string(str, &mask))
    {
      set_verbosity(mask);
      return L4_EOK;
    }

  char const *eq = strchr(str, '=');
  if (!eq)
    return -L4_EINVAL;

  unsigned c;
  if (!component_from_string(str, eq - str, &c) ||
      !verbosity_mask_from_string(eq + 1, &mask))
    {
      return -L4_EINVAL;
    }

  set_verbosity(c, mask);

  return L4_EOK;
}
