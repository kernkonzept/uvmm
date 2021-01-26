/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 */

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/inhibitor>
#include <l4/vbus/vbus_inhibitor.h>

#include "debug.h"
#include "pm.h"

namespace Vmm {

Pm::Pm()
{}

Pm::~Pm()
{}

bool
Pm::acquire_wakeup_inhibitor()
{ return true; }

bool
Pm::suspend()
{ return true; }

void
Pm::free_inhibitors()
{ }

void
Pm::shutdown(bool)
{ }

void
Pm::resume()
{ }

}
