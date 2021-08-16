/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <l4/sys/types.h>

namespace Riscv {

enum : l4_umword_t {
  Msb = static_cast<l4_umword_t>(1) << (L4_MWORD_BITS - 1),
};

enum : l4_umword_t {
  Int_user_software               =  0 | Msb,
  Int_virtual_supervisor_software =  2 | Msb,
  Int_supervisor_software         =  1 | Msb,
  Int_user_timer                  =  4 | Msb,
  Int_supervisor_timer            =  5 | Msb,
  Int_virtual_supervisor_timer    =  6 | Msb,
  Int_user_external               =  8 | Msb,
  Int_supervisor_external         =  9 | Msb,
  Int_virtual_supervisor_external = 10 | Msb,
};

enum : l4_umword_t
{
  Exc_inst_misaligned        = 0,
  Exc_inst_access            = 1,
  Exc_illegal_inst           = 2,
  Exc_breakpoint             = 3,
  Exc_load_acesss            = 5,
  Exc_store_acesss           = 7,
  Exc_ecall                  = 8,
  Exc_hcall                  = 10,
  Exc_inst_page_fault        = 12,
  Exc_load_page_fault        = 13,
  Exc_store_page_fault       = 15,
  Exc_guest_inst_page_fault  = 20,
  Exc_guest_load_page_fault  = 21,
  Exc_virtual_inst           = 22,
  Exc_guest_store_page_fault = 23,
};

enum : l4_umword_t
{
  L4_ipc_upcall       = 0x18,
  L4_exregs_exception = 0x19,
};

enum : l4_umword_t
{
  Sstatus_sie  = 1 << 1,
  Sstatus_spie = 1 << 5,
  Sstatus_spp  = 1 << 8,
};

enum : l4_umword_t
{
  Hstatus_spvp  = 1 << 8,
};

enum : l4_umword_t
{
  Stvec_mode_direct   = 0,
  Stvec_mode_vectored = 1,
  Stvec_mode_mask     = 3,
};

}
