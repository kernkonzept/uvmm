/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 */

#include "guest.h"

namespace Vmm {

void
Guest::add_sys_reg_aarch64(unsigned, unsigned,
                           unsigned, unsigned,
                           unsigned,
                           cxx::Ref_ptr<Vmm::Arm::Sys_reg> const &)
{}

}
