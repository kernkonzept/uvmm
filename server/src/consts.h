/*
 * Copyright (C) 2016-2017, 2021 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

namespace Vmm {

enum Handler_return_codes
{
  Retry = 0,
  Jump_instr = 1,
  Invalid_opcode = 2,     // Handled on amd64 only.
  Stack_fault = 3,        // Handled on amd64 only.
  General_protection = 4, // Handled on amd64 only.
};

enum
{
  Ram_hugepageshift  = 24,
  Ram_hugepagesize   = 1UL << Ram_hugepageshift,
};

} // namespace Vmm
