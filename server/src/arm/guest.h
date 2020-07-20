/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2015-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */
#pragma once

#include <vector>
#include <unordered_map>

#include <l4/cxx/ref_ptr>
#include <l4/sys/vm>

#include "core_timer.h"
#include "device.h"
#include "device_tree.h"
#include "generic_guest.h"
#include "gic_iface.h"
#include "vm_ram.h"
#include "cpu_dev_array.h"
#include "smccc_device.h"
#include "sys_reg.h"
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

  Guest();

  void setup_device_tree(Vdev::Device_tree) {}

  l4_addr_t load_linux_kernel(Vm_ram *ram, char const *kernel,
                              Ram_free_list *free_list);

  void prepare_platform(Vdev::Device_lookup *devs)
  { _cpus = devs->cpus(); }

  void prepare_vcpu_startup(Vcpu_ptr vcpu, l4_addr_t entry) const;

  void prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry,
                         Vm_ram *ram, char const *kernel,
                         char const *cmd_line, l4_addr_t dt);
  void run(cxx::Ref_ptr<Cpu_dev_array> cpus);

  void L4_NORETURN halt_vm()
  {
    stop_cpus();
    Generic_guest::halt_vm();
  }

  void L4_NORETURN shutdown(int val)
  {
    stop_cpus();
    Generic_guest::shutdown(val);
  }

  l4_msgtag_t handle_entry(Vcpu_ptr vcpu);

  static Guest *create_instance();

  void show_state_interrupts(FILE *, Vcpu_ptr) {}

  cxx::Ref_ptr<Gic::Dist_if> gic() const
  { return _gic; }

  void set_timer(cxx::Ref_ptr<Vdev::Core_timer> &timer)
  { _timer = timer; }

  void wait_for_timer_or_irq(Vcpu_ptr vcpu);

  enum Smccc_method
  {
    Smc,
    Hvc,
    Num_smcc_methods
  };

  void register_vm_handler(Smccc_method method,
                           cxx::Ref_ptr<Vmm::Smccc_device> const &handler)
  {
    _smccc_handlers[method].push_back(handler);
  }

  template <Smccc_method METHOD>
  void handle_smccc_call(Vcpu_ptr vcpu)
  {
    bool res = false;
    // Check if this is a valid/supported SMCCC call
    if (Smccc_device::is_valid_call(vcpu->r.r[0]))
      {
        unsigned imm = vcpu.hsr().svc_imm();
        for (auto const &h: _smccc_handlers[METHOD])
          if ((res = h->vm_call(imm, vcpu)))
            break;
      }

    if (!res)
      {
        warn().printf("No handler for %s call: imm=%x a0=%lx a1=%lx ip=%lx "
                      "lr=%lx\n",
                      (METHOD == Smc) ? "SMC" : "HVC",
                      static_cast<unsigned>(vcpu.hsr().svc_imm()),
                      vcpu->r.r[0], vcpu->r.r[1],
                      vcpu->r.ip, vcpu.get_lr());
        vcpu->r.r[0] = Smccc_device::Not_supported;
      }

    if (METHOD == Smc)
      vcpu->r.ip += 4;
  }

  void map_gicc(Vdev::Device_lookup *devs, Vdev::Dt_node const &node) const;
  void handle_wfx(Vcpu_ptr vcpu);
  void handle_ppi(Vcpu_ptr vcpu);

  void handle_ex_regs_exception(Vcpu_ptr vcpu);

  using Sys_reg = Vmm::Arm::Sys_reg;

  cxx::Weak_ptr<Sys_reg> sys_reg(Sys_reg::Key k)
  { return _sys_regs.at(k); }

  void add_sys_reg_aarch32(unsigned cp, unsigned op1,
                           unsigned crn, unsigned crm,
                           unsigned op2,
                           cxx::Ref_ptr<Sys_reg> const &r)
  {
    _sys_regs[Sys_reg::Key::cp_r(cp, op1, crn, crm, op2)] = r;
  }

  void add_sys_reg_aarch32_cp64(unsigned cp, unsigned op1,
                                unsigned crm,
                                cxx::Ref_ptr<Sys_reg> const &r)
  {
    _sys_regs[Sys_reg::Key::cp_r_64(cp, op1, crm)] = r;
  }

  void add_sys_reg_aarch64(unsigned op0, unsigned op1,
                           unsigned crn, unsigned crm,
                           unsigned op2,
                           cxx::Ref_ptr<Sys_reg> const &r);

  void add_sys_reg_both(unsigned op0, unsigned op1,
                        unsigned crn, unsigned crm,
                        unsigned op2,
                        cxx::Ref_ptr<Sys_reg> const &r)
  {
    add_sys_reg_aarch64(op0, op1, crn, crm, op2, r);
    // op0 == 3 -> cp15, op0 == 2 -> cp14
    add_sys_reg_aarch32(op0 + 12, op1, crn, crm, op2, r);
  }

private:

  void check_guest_constraints(l4_addr_t ram_base) const;
  void arm_update_device_tree();
  void stop_cpus();

  cxx::Ref_ptr<Gic::Dist_if> _gic;
  cxx::Ref_ptr<Vdev::Core_timer> _timer;
  cxx::Ref_ptr<Cpu_dev_array> _cpus;
  bool guest_64bit = false;

  std::vector<cxx::Ref_ptr<Vmm::Smccc_device>> _smccc_handlers[Num_smcc_methods];
  std::unordered_map<Sys_reg::Key, cxx::Ref_ptr<Sys_reg>> _sys_regs;
};

} // namespace
