/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/sys/l4int.h>
#include <map>

#include "mmio_device.h"

struct Region
{
  l4_addr_t start;
  l4_addr_t end; // inclusive

  Region() {}
  Region(l4_addr_t a) : start(a), end(a) {}
  Region(l4_addr_t s, l4_addr_t e) : start(s), end(e) {}

  static Region ss(l4_addr_t start, l4_size_t size)
  { return Region(start, start + size - 1); }

  bool operator < (Region const &r) const { return end < r.start; }

  bool contains(Region const &r) const
  { return (start <= r.start) && (r.end <= end); } // [ [ ... ] ]
};

typedef std::map<Region, cxx::Ref_ptr<Vmm::Mmio_device>> Vm_mem;
