/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2022 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */
/**
 * Central hub that allows to connect external wallclock time source.
 */
#include <l4/sys/types.h>
#include <time.h>

namespace Vdev {

class L4rtc_adapter
{
public:
  virtual l4_uint64_t ns_since_epoch() = 0;
};

class L4rtc_hub
{
  static L4rtc_adapter *_adapter;

public:
  static void invalidate()
  { _adapter = nullptr; }

  static l4_uint64_t ns_since_epoch()
  {
    if (_adapter)
      return _adapter->ns_since_epoch();
    return time(NULL) * 1000000000;
  }

  static void register_adapter(L4rtc_adapter *adapter)
  { _adapter = adapter; }
};

} // Vdev
