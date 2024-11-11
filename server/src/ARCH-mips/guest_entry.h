/*
 * Copyright (C) 2016-2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/sys/vcpu.h>

/// Entry point for guest exits.
void c_vcpu_entry(l4_vcpu_state_t *vcpu);
/// Entry point for newly created vcpu threads.
void *powerup_handler(void *vcpu);
