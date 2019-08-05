/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace Monitor {

inline std::vector<std::string>
split_params(char const *str, unsigned max_params = 0)
{
  if (strlen(str) == 0)
    return {};

  std::vector<std::string> res;

  char const *beg = str;
  char const *next_sep;

  for (;;)
    {
      next_sep = strchr(beg, ' ');

      if (next_sep)
        {
          res.emplace_back(beg, next_sep - beg);

          if (max_params && res.size() == max_params - 1)
            {
              res.emplace_back(next_sep + 1);
              break;
            }
        }
      else
        {
          res.emplace_back(beg);
          break;
        }

      beg = next_sep + 1;
    }

  return res;
}

inline void
simple_complete(FILE *f, char const *args, std::vector<char const *> subcmds)
{
  size_t arglen = strlen(args);

  for (char const *subcmd : subcmds)
    {
      if (strncmp(args, subcmd, arglen) == 0)
        fprintf(f, "%s\n", subcmd);
    }
}

inline bool
stou(char const *str, unsigned *i)
{
  errno = 0;

  char *endptr;
  unsigned long long ill = strtoull(str, &endptr, 10);

  bool success = errno == 0
                 && !*endptr
                 && ill <= INT_MAX;

  if (success)
    *i = ill;

  return success;
}

}
