/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "debug.h"

namespace Varch {

void inline
check_mem_base(l4_addr_t membase)
{
  Dbg warn(Dbg::Mmio, Dbg::Warn, "ram");
  if (membase & ((1UL << 27) - 1))
    warn.printf(
      "\033[01;31mWARNING: Guest memory not 128MB aligned!\033[m\n"
      "       If you run Linux as a guest, Linux will likely fail to boot\n"
      "       as it assumes a 128MB alignment of its memory.\n"
      "       Current guest RAM alignment is only %dMB\n",
      (1 << __builtin_ctz(membase)) >> 20);
  else if (membase & ~0xf0000000)
    warn.printf(
        "WARNING: Guest memory not 256MB aligned!\n"
        "       If you run Linux as a guest, you might hit a bug\n"
        "       in the arch/arm/boot/compressed/head.S code\n"
        "       that misses an ISB after code has been relocated.\n"
        "       According to the internet a fix for this issue\n"
        "       is floating around.\n");
}

}
