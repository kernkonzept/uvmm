/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

enum E820_types
{
  E820_ram = 1,
  E820_reserved = 2
};

struct E820_entry
{
  l4_uint64_t addr; // start of segment
  l4_uint64_t size;
  l4_uint32_t type;
} __attribute__((packed));
