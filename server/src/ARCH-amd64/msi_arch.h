/*
 * Copyright (C) 2019-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/bitfield>

namespace Vdev { namespace Msix {

enum Table_entry_const_arch
{
  Data_vector_mask = 0xff,
  Address_interrupt_prefix = 0xfee,
};

/// MSI-X address: Interrupt request compatibility format (Intel)
struct Interrupt_request_compat
{
  l4_uint64_t raw;
  CXX_BITFIELD_MEMBER(40, 63, dest_id_upper, raw);
  CXX_BITFIELD_MEMBER(32, 39, reserved0_2, raw);
  CXX_BITFIELD_MEMBER(20, 31, fixed, raw);
  CXX_BITFIELD_MEMBER(12, 19, dest_id, raw);
  CXX_BITFIELD_MEMBER(4, 11, reserved0_1, raw);
  CXX_BITFIELD_MEMBER(3, 3, redirect_hint, raw);
  CXX_BITFIELD_MEMBER(2, 2, dest_mode, raw);
  CXX_BITFIELD_MEMBER(0, 1, reserved_0, raw);

  explicit Interrupt_request_compat(l4_uint64_t addr) : raw(addr)
  {}
};

enum Delivery_mode : l4_uint8_t
{
  Dm_fixed = 0,
  Dm_lowest_prio = 1,
  Dm_smi = 2,
  Dm_nmi = 4,
  Dm_init = 5,
  Dm_startup = 6,
  Dm_extint = 7,
};

/// MSI-X data format (Intel)
struct Data_register_format
{
  // Intel SDM Vol. 3A 10-35, October 2017
  l4_uint64_t raw;
  CXX_BITFIELD_MEMBER(15, 15, trigger_mode, raw);
  CXX_BITFIELD_MEMBER(14, 14, trigger_level, raw);
  CXX_BITFIELD_MEMBER(8, 10, delivery_mode, raw);
  CXX_BITFIELD_MEMBER(0, 7, vector, raw);

  explicit Data_register_format(l4_uint64_t data) : raw(data)
  {}
};

}} // namespace Vdev::Msix
