/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch christian.poetzsch@kernkonzept.com
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <vector>
#include <string>
#include <device.h>

struct Ic
{
  Ic()
  { _ics.push_back(this); }

  static Ic* ic(const std::string &name)
  {
    for (auto a: _ics)
      if (a->provides() == name)
        return a;
    return nullptr;
  }

  static Ic* default_ic(const Arch &arch)
  {
    for (auto a: _ics)
      if (a->provides() == arch.ic)
        return a;
    return nullptr;
  }

  virtual std::string provides() const = 0;
  virtual std::vector<unsigned> next_irq() = 0;

  static std::vector<Ic*> _ics;
};
