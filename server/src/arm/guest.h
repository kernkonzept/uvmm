/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/sys/vm>

#include "core_timer.h"
#include "device.h"
#include "device_tree.h"
#include "generic_guest.h"
#include "gic.h"
#include "vm_ram.h"
#include "cpu_dev_array.h"
#include "smccc_device.h"
#include "vmprint.h"

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

  enum
  {
    Shutdown = 0x0,
    Reboot = 0x66
  };

  Guest();

  void setup_device_tree(Vdev::Device_tree) {}

  l4_addr_t load_linux_kernel(Vm_ram *ram, char const *kernel,
                              Ram_free_list *free_list);

  void prepare_vcpu_startup(Vcpu_ptr vcpu, l4_addr_t entry) const;

  void prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry,
                         Vm_ram *ram, char const *kernel,
                         char const *cmd_line, l4_addr_t dt);
  void run(cxx::Ref_ptr<Cpu_dev_array> cpus);

  void L4_NORETURN shutdown(int val);

  l4_msgtag_t handle_entry(Vcpu_ptr vcpu);

  static Guest *create_instance();

  void show_state_interrupts(FILE *, Vcpu_ptr) {}

  cxx::Ref_ptr<Gic::Dist> gic() const
  { return _gic; }

  void set_timer(cxx::Ref_ptr<Vdev::Core_timer> &timer)
  { _timer = timer; }

  void wait_for_timer_or_irq(Vcpu_ptr vcpu);

  enum Smccc_method
  {
    Smc,
    Hvc
  };

  void register_vm_handler(Smccc_method method,
                           cxx::Ref_ptr<Vmm::Smccc_device> const &handler)
  {
    switch (method)
    {
    case Smc: _smc_handlers.push_back(handler); break;
    case Hvc: _hvc_handlers.push_back(handler); break;
    }
  }

  void handle_vm_call(Vcpu_ptr vcpu);
  void handle_smc_call(Vcpu_ptr vcpu);

  void map_gicc(Vdev::Device_lookup *devs, Vdev::Dt_node const &node) const;
  void handle_wfx(Vcpu_ptr vcpu);
  void handle_ppi(Vcpu_ptr vcpu);

  void handle_ex_regs_exception(Vcpu_ptr vcpu);

  Pm &pm()
  { return _pm; }

private:

  void check_guest_constraints(l4_addr_t ram_base) const;
  void arm_update_device_tree();

  cxx::Ref_ptr<Gic::Dist> _gic;
  cxx::Ref_ptr<Vdev::Core_timer> _timer;
  cxx::Ref_ptr<Cpu_dev_array> _cpus;
  bool guest_64bit = false;

  std::vector<cxx::Ref_ptr<Vmm::Smccc_device>> _hvc_handlers;
  std::vector<cxx::Ref_ptr<Vmm::Smccc_device>> _smc_handlers;
};

} // namespace
