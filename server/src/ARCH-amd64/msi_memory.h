/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "generic_msi_memory.h"
#include "msi.h"
#include "msi_arch.h"
#include "virt_lapic.h"
#include "mem_types.h"
#include "msi_controller.h"

namespace Vdev { namespace Msix {

inline cxx::Ref_ptr<Virt_msix_table>
make_virt_msix_table(cxx::Ref_ptr<Vdev::Mmio_ds_converter> &&con,
                     cxx::Ref_ptr<Vdev::Msi::Allocator> msi_alloc,
                     Vmm::Guest *vmm,
                     l4_uint64_t src_id,
                     unsigned num_entries,
                     cxx::Ref_ptr<Gic::Msix_controller> const &msix_ctrl)
{
  auto hdlr =
    make_device<Msix::Virt_msix_table>(std::move(con), msi_alloc,
                                       vmm->registry(), src_id, num_entries,
                                       msix_ctrl);

  return hdlr;
}
}} // namespace Vdev::Msix
