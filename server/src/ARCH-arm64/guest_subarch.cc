/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#include "guest.h"

namespace Vmm {

void
Guest::add_sys_reg_aarch64(unsigned op0, unsigned op1,
                           unsigned crn, unsigned crm,
                           unsigned op2,
                           cxx::Ref_ptr<Vmm::Arm::Sys_reg> const &r)
{
  _sys_regs[Vmm::Arm::Sys_reg::Key::sr(op0, op1, crn, crm, op2)] = r;
}

}
