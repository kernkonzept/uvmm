/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>

#include "core_timer.h"
#include "device.h"
#include "generic_guest.h"
#include "gic.h"
#include "ram_ds.h"
#include "vcpu.h"

namespace Vmm {

/**
 * ARM virtual machine monitor.
 */
class Guest : public Generic_guest
{
public:
  enum { Default_rambase = Ram_ds::Ram_base_identity_mapped };

  Guest(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base);

  L4virtio::Ptr<void> load_linux_kernel(char const *kernel, l4_addr_t *entry);

  void prepare_linux_run(Cpu vcpu, l4_addr_t entry, char const *kernel,
                         char const *cmd_line);
  void run(Cpu vcpu);

  l4_msgtag_t handle_entry(Cpu vcpu);

  static Guest *create_instance(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base);

  void show_state_registers(FILE *) override;
  void show_state_interrupts(FILE *) override;

  cxx::Ref_ptr<Gic::Dist> gic() const
  { return _gic; }

  cxx::Ref_ptr<Vdev::Core_timer> timer() const
  { return _timer; }

private:
  cxx::Ref_ptr<Gic::Dist> _gic;
  cxx::Ref_ptr<Vdev::Core_timer> _timer;
};

} // namespace
