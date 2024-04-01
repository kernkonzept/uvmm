/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2015-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */
#pragma once

#include <vector>
#include <map>

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
    Default_rambase = 0,
    Boot_offset = 0
  };

  Guest();

  static bool fault_mode_supported(Fault_mode mode);

  void setup_device_tree(Vdev::Device_tree) {}

  l4_addr_t load_binary(Vm_ram *ram, char const *binary,
                        Ram_free_list *free_list);

  void prepare_platform(Vdev::Device_lookup *devs)
  { _cpus = devs->cpus(); }

  void prepare_vcpu_startup(Vcpu_ptr vcpu, l4_addr_t entry) const;

  void prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const *binary, char const *cmd_line,
                          l4_addr_t dt_boot_addr);
  void run(cxx::Ref_ptr<Cpu_dev_array> cpus);

  void cpu_online(Cpu_dev *cpu);
  void cpu_offline(Cpu_dev *cpu);
  void sync_all_other_cores_off() const override;

  void L4_NORETURN halt_vm(Vcpu_ptr current_vcpu) override
  {
    stop_cpus();
    sync_all_other_cores_off();
    Generic_guest::halt_vm(current_vcpu);
  }

  void L4_NORETURN shutdown(int val) override
  {
    stop_cpus();
    Generic_guest::shutdown(val);
  }

  l4_msgtag_t handle_entry(Vcpu_ptr vcpu);

  static Guest *create_instance();
  static Guest *instance();

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

    // Skip HVC/SMC instruction here. Some vm_call() methods like
    // Psci_device::vm_call() might set it to a completly different value, which
    // we can not change without breaking things.
    vcpu->r.ip += 4;

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
        // Strip register values if the guest is executed in 32-bit mode.
        l4_umword_t mask = (vcpu->r.flags & 0x10) ? ~0U : ~0UL;
        warn().printf("No handler for %s call: imm=%x a0=%lx a1=%lx ip=%lx "
                      "lr=%lx\n",
                      (METHOD == Smc) ? "SMC" : "HVC",
                      static_cast<unsigned>(vcpu.hsr().svc_imm()),
                      vcpu->r.r[0] & mask, vcpu->r.r[1] & mask,
                      (vcpu->r.ip - 4) & mask, vcpu.get_lr() & mask);
        vcpu->r.r[0] = Smccc_device::Not_supported;
      }
  }

  void handle_wfx(Vcpu_ptr vcpu);
  void handle_ppi(Vcpu_ptr vcpu);

  bool inject_abort(Vcpu_ptr vcpu, bool inst, l4_addr_t addr);
  bool inject_undef(Vcpu_ptr vcpu);

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

protected:
  bool inject_abort(l4_addr_t addr, Vcpu_ptr vcpu) override;

private:

  void check_guest_constraints(l4_addr_t ram_base) const;
  void arm_update_device_tree();
  void stop_cpus();

  cxx::Ref_ptr<Gic::Dist_if> _gic;
  cxx::Ref_ptr<Vdev::Core_timer> _timer;
  cxx::Ref_ptr<Cpu_dev_array> _cpus;
  bool _guest_64bit = false;

  std::vector<cxx::Ref_ptr<Vmm::Smccc_device>> _smccc_handlers[Num_smcc_methods];
  std::map<Sys_reg::Key, cxx::Ref_ptr<Sys_reg>> _sys_regs;
};

} // namespace
