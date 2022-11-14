/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include "const.h"

#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>

constexpr OutFormat Default_format = Txt;

namespace Writer
{
  static void out(const std::string &name, const void *addr, size_t size)
  {
    if (name == "--")
      std::cout.write((const char*)addr, size);
    else
      {
        std::ofstream o(name, std::ios::out);
        o.write((const char*)addr, size);
        o.close();
      }
  }
};
