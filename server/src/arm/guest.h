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
#include "device_tree.h"
#include "generic_guest.h"
#include "gic.h"
#include "ram_ds.h"
#include "cpu_dev_array.h"

namespace Vmm {

/**
 * ARM virtual machine monitor.
 */
class Guest : public Generic_guest
{
public:
  enum
  {
    Default_rambase = Ram_ds::Ram_base_identity_mapped,
    Boot_offset = 0
  };

  Guest();

  void setup_device_tree(Vdev::Device_tree dt);

  L4virtio::Ptr<void> load_linux_kernel(Ram_ds *ram, char const *kernel,
                                        l4_addr_t *entry);

  void prepare_vcpu_startup(Vcpu_ptr vcpu, l4_addr_t entry) const;

  void prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry,
                         Ram_ds *ram, char const *kernel,
                         char const *cmd_line, l4_addr_t dt);
  void run(cxx::Ref_ptr<Cpu_dev_array> cpus);
  void reset_vcpu(Vcpu_ptr vcpu);

  l4_msgtag_t handle_entry(Vcpu_ptr vcpu);

  static Guest *create_instance();

  void show_state_interrupts(FILE *, Vcpu_ptr) {}

  cxx::Ref_ptr<Gic::Dist> gic() const
  { return _gic; }

  cxx::Ref_ptr<Vdev::Core_timer> timer() const
  { return _timer; }

  void handle_wfx(Vcpu_ptr vcpu);
  void handle_ppi(Vcpu_ptr vcpu);
  bool handle_psci_call(Vcpu_ptr vcpu);

private:
  Cpu_dev *lookup_cpu(l4_uint32_t hwid) const;
  void check_guest_constraints(Ram_ds *ram);
  void arm_update_device_tree();

  cxx::Ref_ptr<Gic::Dist> _gic;
  cxx::Ref_ptr<Vdev::Core_timer> _timer;
  bool guest_64bit = false;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
};

} // namespace
