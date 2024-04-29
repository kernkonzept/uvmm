/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include "cpu_dev_array.h"
#include "generic_guest.h"
#include "plic.h"
#include "sbi.h"
#include "vcpu_ic.h"
#include "virtual_timer.h"
#include "vm_ram.h"

namespace Vmm {

class Guest : public Generic_guest
{
public:
  enum
  {
    Default_rambase = 0,
    Boot_offset = 0
  };

  static Guest *create_instance();

  Guest();

  void setup_device_tree(Vdev::Device_tree);

  void set_plic(cxx::Ref_ptr<Gic::Plic> &plic)
  { _plic = plic; }

  l4_addr_t load_binary(Vm_ram *ram, char const *binary,
                        Ram_free_list *free_list);

  void prepare_platform(Vdev::Device_lookup *devs);

  void prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const *binary, char const *cmd_line,
                          l4_addr_t dt_boot_addr);

  void run(cxx::Ref_ptr<Cpu_dev_array> const &cpus);

  void sync_all_other_cores_off() const override;

  void L4_NORETURN halt_vm(Vcpu_ptr current_vcpu) override;
  void L4_NORETURN shutdown(int val) override;

  void wfi(Vcpu_ptr vcpu);

  void handle_entry(Vcpu_ptr vcpu);
  void handle_ipc_upcall(Vcpu_ptr vcpu);
  void handle_exregs_exception(Vcpu_ptr vcpu);
  void handle_ecall(Vcpu_ptr vcpu);
  void handle_page_fault(Vcpu_ptr vcpu);
  void handle_virtual_inst(Vcpu_ptr vcpu);

  static void vcpu_entry(l4_vcpu_state_t *vcpu);

  cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const
  { return _cpus; }

  cxx::Ref_ptr<Vmm::Vm_ram> ram() const
  { return _ram; }

  Cpu_dev *lookup_cpu(l4_umword_t vcpu_id) const;

  cxx::Ref_ptr<Gic::Vcpu_ic> get_vcpu_ic(Vcpu_ptr vcpu)
  { return _vcpu_ics[vcpu.get_vcpu_id()]; }

  bool has_vstimecmp() const
  { return _has_vstimecmp; }

  cxx::Ref_ptr<Vdev::Virtual_timer> get_timer(Vcpu_ptr vcpu)
  { return _timers[vcpu.get_vcpu_id()]; }

  void register_sbi_ext_handler(l4_int32_t ext_id, cxx::Ref_ptr<Sbi_ext> handler)
  { _sbi->register_ext(ext_id, handler); }

private:
  void stop_cpus();

  void redirect_trap(Vcpu_ptr vcpu);

  static void fetch_guest_inst(Vcpu_ptr vcpu);
  static l4_uint16_t read_guest_mem_inst(l4_addr_t guest_virt_addr,
                                         l4_vm_state_t *vm_state,
                                         bool *failed);

  bool _has_vstimecmp;

  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
  std::vector<cxx::Ref_ptr<Gic::Vcpu_ic>> _vcpu_ics;
  std::vector<cxx::Ref_ptr<Vdev::Virtual_timer>> _timers;
  cxx::Ref_ptr<Gic::Plic> _plic;
  Sbi *_sbi;
};

} // namespace
