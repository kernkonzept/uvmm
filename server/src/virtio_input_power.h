/*
 * Copyright (C) 2015-2018 Kernkonzept GmbH.
 * Author(s): Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once
#include "virtio_input.h"
namespace Vdev
{
int do_inject_events(Virtio_input_event *events, size_t num);
void do_inject_sysreq_event(unsigned char);
}
