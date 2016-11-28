/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author: Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *         Adam Lackorzynski <adam@l4re.org>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/vbus/vbus>
#include <l4/sys/platform_control>

/**
 * Guest interface for system power control.
 *
 * Allows the guest to control machine suspend/shutdown. The underlying
 * technique is inhibitors that -if taken- prevent the system from
 * suspending/shutting down/rebooting. This interface acquires suspend and
 * shutdown inhibitors. It allows the guest to release them.
 *
 * If a L4::Platform control cap 'pfc' is available, this interface will
 * announce the guest's intent to this cap as well. This can be used to allow
 * a guest to suspend/shutdown/reboot the machine.
 */
class Pm
{
public:
  Pm();
  ~Pm();

  /**
   * Configure if guest should resume on system resume.
   *
   * If true, uvmm will acquire a wakeup inhibitor prior to releasing its
   * suspend inhibitor. IO sends a wakeup event to all clients holding a
   * wakeup inhibitor on system resume. This can be used to resume the guest
   * on system resume.
   */
  void use_wakeup_inhibitor(bool val)
  {
    _use_wakeup_inhibitor = val;
  }

  bool suspend();
  void resume();
  void shutdown(bool reboot = false);
  void free_inhibitors();

private:
  L4::Cap<L4Re::Inhibitor> _vbus;
  L4::Cap<L4::Platform_control> _pfc;

  bool _use_wakeup_inhibitor = true;

  /**
   * \pre _vbus must be valid
   */
  bool acquire_wakeup_inhibitor();
};
