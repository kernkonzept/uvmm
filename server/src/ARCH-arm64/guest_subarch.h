/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

namespace Vmm {

enum { Guest_64bit_supported = true };

void
Guest::add_sys_reg_aarch64(unsigned op0, unsigned op1,
                           unsigned crn, unsigned crm,
                           unsigned op2,
                           cxx::Ref_ptr<Sys_reg> const &r)
{
  _sys_regs[Sys_reg::Key::sr(op0, op1, crn, crm, op2)] = r;
}

}
