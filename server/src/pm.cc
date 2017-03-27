/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *         Adam Lackorzynski <adam@l4re.org>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/inhibitor>
#include <l4/vbus/vbus_inhibitor.h>

#include "debug.h"
#include "pm.h"

static Dbg warn(Dbg::Pm, Dbg::Warn, "pm");

Pm::Pm()
: _vbus(L4Re::Env::env()->get_cap<L4Re::Inhibitor>("vbus"))
{
  // vbus is optional
  if (_vbus)
    {
      // If we have a 'vbus', we assume we also have devices to hand out to
      // the guest. If acquiring the suspend and shutdown inhibitors fails,
      // the system can be suspended or shutdown anytime. If we handed out
      // devices to the guest, this could result in erroneous system
      // states. Therefore failure to acquire an inhibitor is fatal.
      int r = 0;
      if ((r = _vbus->acquire(L4VBUS_INHIBITOR_SUSPEND, "vm running")))
        {
          warn.printf("Failed to acquire suspend inhibitor: %d.\n", r);
          L4Re::chksys(-L4_ENOENT, "acquire suspend inhibitor");
        }

      if ((r = _vbus->acquire(L4VBUS_INHIBITOR_SHUTDOWN, "vm running")))
        {
          warn.printf("Failed to acquire shutdown inhibitor: %d.\n", r);
          _vbus->release(L4VBUS_INHIBITOR_SUSPEND);
          L4Re::chksys(-L4_ENOENT, "acquire shutdown inhibitor");
        }
    }

  // pfc cap is optional, but when its there, it should be used
  _pfc = L4Re::Env::env()->get_cap<L4::Platform_control>("pfc");
}

Pm::~Pm()
{
  free_inhibitors();
}

bool
Pm::acquire_wakeup_inhibitor()
{
  if (!_use_wakeup_inhibitor)
    return true;

  int r = _vbus->acquire(L4VBUS_INHIBITOR_WAKEUP, "wakeup");
  if (r < 0)
    warn.printf("Failed to acquire wakeup inhibitor: %d.\n", r);

  return r >= 0;
}

bool
Pm::suspend()
{
  if (_vbus)
    {
      // If we did not get the wakeup inhibitor we will not get wakeup events
      // therefore we deem suspend unsuccessful and wake up the guest
      // immediately, so that it can do something useful.
      if (!acquire_wakeup_inhibitor())
        return false;

      // If we fail to release the suspend inhibitor, we block the system from
      // suspending. This is a state that would not be recoverable without a
      // reboot. Therefore this is a failed suspend, we free the wakeup
      // inhibitor and resume the guest so that it can do something useful.
      int r = _vbus->release(L4VBUS_INHIBITOR_SUSPEND);
      if (r < 0)
        {
          warn.printf("Failed to release suspend inhibitor: %d.\n", r);
          if (_use_wakeup_inhibitor)
            _vbus->release(L4VBUS_INHIBITOR_WAKEUP);
          return false;
        }
    }

  // If we have a pfc cap and we have the wakeup inhibitor, we assume we are
  // woken up by a wakeup event. The wakeup event will only come after the
  // system successfully suspended and was subsequently woken up. Therefore it
  // is an error if the system_suspend call failed. We have to get the suspend
  // inhibitor again, possibly free the wakeup inhibitor and return to the
  // guest immediately, so that it can so do something useful.
  if (_pfc && (l4_error(_pfc->system_suspend(0)) < 0))
    {
      warn.printf("Call to do system suspend failed.\n");

      if (!_vbus)
        return false;

      _vbus->acquire(L4VBUS_INHIBITOR_SUSPEND, "vm running");
      if (_use_wakeup_inhibitor)
        _vbus->release(L4VBUS_INHIBITOR_WAKEUP);

      return false;
    }

  return true;
}

void
Pm::free_inhibitors()
{
  if (!_vbus)
    return;

  if (_vbus->release(L4VBUS_INHIBITOR_SHUTDOWN))
    warn.printf("Failed to release shutdown inhibitor.\n");
  if (_vbus->release(L4VBUS_INHIBITOR_SUSPEND))
    warn.printf("Failed to release suspend inhibitor.\n");
}

void
Pm::shutdown(bool reboot)
{
  free_inhibitors();

  if (_pfc && l4_error(_pfc->system_shutdown(reboot)))
    warn.printf("Call to shutdown failed.\n");
}

void
Pm::resume()
{
  if (_vbus)
    {
      // Failure to acquire an inhibitor is a problem (see description
      // above). However, at this time the guest already has a lot of state
      // that we would loose if we would crash here. Therefore we warn the
      // operator that aquiring the inhibitor fails but do not bail out.
      int r = 0;
      if ((r = _vbus->acquire(L4VBUS_INHIBITOR_SUSPEND, "vm running")))
        warn.printf("Failed to release suspend inhibitor: %d.\n", r);

      if (_use_wakeup_inhibitor
          && (r = _vbus->release(L4VBUS_INHIBITOR_WAKEUP)))
        warn.printf("Failed to release wakeup inhibitor: %d.\n", r);
    }
}
