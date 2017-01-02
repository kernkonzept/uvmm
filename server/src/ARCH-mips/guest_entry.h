/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/vcpu.h>

/// Entry point for guest exits.
void c_vcpu_entry(l4_vcpu_state_t *vcpu);
/// Entry point for newly created vcpu threads.
void *powerup_handler(void *vcpu);
