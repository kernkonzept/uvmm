/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 */
/**
 * Central hub that allows to connect external wallclock time source.
 */
#include <l4/sys/types.h>

namespace Vdev{

class L4rtc_adapter
{
public:
  virtual l4_uint64_t ns_since_epoch() = 0;
};

class L4rtc_hub
{
  static L4rtc_hub *_l4rtc;
  L4rtc_adapter *_adapter = nullptr;

public:
  static L4rtc_hub *get()
  {
    if (!_l4rtc)
      _l4rtc = new L4rtc_hub();
    return _l4rtc;
  };

  static void destroy()
  {
    if (_l4rtc)
      delete _l4rtc;
    _l4rtc = nullptr;
  }

  l4_uint64_t ns_since_epoch()
  {
    if (_adapter)
      return _adapter->ns_since_epoch();
    return 0;
  }

  void register_adapter(L4rtc_adapter *adapter)
  { _adapter = adapter; }
};

} // Vdev
