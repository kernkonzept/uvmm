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

#include "debug.h"
#include "mmio_device.h"
#include "mem_types.h"

namespace Vmm {

class Vm_mem : public std::map<Region, cxx::Ref_ptr<Vmm::Mmio_device>>
{
public:
  void add_mmio_device(Region const &region,
                       cxx::Ref_ptr<Vmm::Mmio_device> const &dev);

  void dump(Dbg::Verbosity l) const;

private:
  void throw_error(char const *msg,
            cxx::Ref_ptr<Vmm::Mmio_device> const &dev, Vmm::Region const &region,
            cxx::Ref_ptr<Vmm::Mmio_device> const &new_dev, Vmm::Region const &new_region);
};

} // namespace
