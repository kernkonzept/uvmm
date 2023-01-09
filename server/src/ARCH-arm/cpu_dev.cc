/*
 * Copyright (C) 2017-2021 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/sys/types.h>

static l4_umword_t read_mvfr0()
{
  l4_umword_t v;
  asm volatile(".fpu vfp\n vmrs %0, mvfr0" : "=r" (v));
  return v;
}

/// 0: only save d0-d15 on vCPU entry.
/// 1: also save d16-d31 on vCPU entry.
l4_umword_t save_32r = (read_mvfr0() & 0xf) == 2;
