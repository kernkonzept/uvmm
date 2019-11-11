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
#include "mem_types.h"

namespace Vmm {

class Vm_mem : public std::map<Region, cxx::Ref_ptr<Vmm::Mmio_device>>
{
public:
  void add_mmio_device(Region const &region,
                       cxx::Ref_ptr<Vmm::Mmio_device> const &dev)
  { add_region(region, dev); }

  void remap_mmio_device(Region const &old_region, Guest_addr const &addr)
  {
    assert(count(old_region) == 1);

    // Save the device
    cxx::Ref_ptr<Vmm::Mmio_device> const dev = at(old_region);

    // Replace old with new
    del_region(old_region);
    add_region(old_region.move(addr), dev);
  }

private:
  void add_region(Region const &region,
                  cxx::Ref_ptr<Vmm::Mmio_device> const &dev);
  void del_region(Region const &region);
};

} // namespace
