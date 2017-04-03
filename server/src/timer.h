/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <vector>
#include <thread>

#include <l4/sys/debugger.h>
#include <pthread-l4.h>

#include <l4/util/util.h>

#include "device.h"

namespace Vdev {

struct Timer : virtual Vdev::Dev_ref
{
  virtual ~Timer() = 0;
  virtual void tick() = 0;
};

inline Timer::~Timer() = default;

class Clock_source
{
public:
  Clock_source()
  : _thread(&Clock_source::run_timer, this)
  {}

  void add_timer(cxx::Ref_ptr<Timer> timer)
  {
    _consumers.push_back(timer);
  }

  void run_timer()
  {
    Dbg().printf("Hello Timer\n");
    l4_debugger_set_object_name(pthread_l4_cap(pthread_self()), "clock timer");

    // now loop forever
    while(1)
      {
        l4_sleep(27);

        for (auto t : _consumers)
          t->tick();
      }
  }

private:
  std::thread _thread;
  std::vector<cxx::Ref_ptr<Timer>> _consumers;
};

} // namespace Vdev
