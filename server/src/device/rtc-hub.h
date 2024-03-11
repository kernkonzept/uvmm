/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */
/**
 * Central hub that allows to connect external wallclock time source.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/sys/kip.h> // l4_kip_clock_ns()
#include <l4/re/env> // l4re_kip()

namespace Vdev {

class L4rtc_adapter
{
public:
  virtual l4_uint64_t ns_since_epoch() = 0;
  virtual void set_ns_since_epoch(l4_uint64_t ns_offset) = 0;
};

class L4rtc_hub
{
  static L4rtc_adapter *_adapter;
  static l4_uint64_t _offset;

public:
  static void invalidate()
  { _adapter = nullptr; }

  static l4_uint64_t ns_since_epoch()
  {
    if (_adapter)
      return _adapter->ns_since_epoch();
    return _offset + l4_kip_clock_ns(l4re_kip());
  }

  static void set_ns_since_epoch(l4_uint64_t ns)
  {
    if (_adapter)
      {
        _adapter->set_ns_since_epoch(ns);
        return;
      }
    _offset = ns - l4_kip_clock_ns(l4re_kip());
  }

  static void register_adapter(L4rtc_adapter *adapter)
  { _adapter = adapter; }
};

} // Vdev
