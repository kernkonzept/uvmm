/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2015-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Jean Wolter <jean.wolter@kernkonzept.com>
 *            Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 */
#include "cpu_dev_array.h"
#include "debug.h"
#include "device_factory.h"
#include "guest.h"

#include "smccc_device.h"

namespace {

using namespace Vdev;

static Dbg warn(Dbg::Dev, Dbg::Warn, "psci");
static Dbg info(Dbg::Dev, Dbg::Info, "psci");

class Psci_device : public Vdev::Device, public Vmm::Smccc_device
{
  enum Psci_error_codes
  {
    Success            = 0,
    Not_supported      = -1,
    Invalid_parameters = -2,
    Denied             = -3,
    Already_on         = -4,
    On_pending         = -5,
    Internal_failure   = -6,
    Not_present        = -7,
    Disabled           = -8,
    Invalid_address    = -9,
  };

  enum Psci_functions
  {
    Psci_version          = 0,
    Cpu_suspend           = 1,
    Cpu_off               = 2,
    Cpu_on                = 3,
    Affinity_info         = 4,
    Migrate               = 5,
    Migrate_info_type     = 6,
    Migrate_info_up_cpu   = 7,
    System_off            = 8,
    System_reset          = 9,
    Psci_features         = 10,
    Cpu_freeze            = 11,
    Cpu_default_suspend   = 12,
    Node_hw_state         = 13,
    System_suspend        = 14,
    Psci_set_suspend_mode = 15,
    Psci_stat_residency   = 16,
    Psci_stat_count       = 17,
  };

  enum Psci_migrate_info
  {
    Tos_up_mig_cap     = 0,
    Tos_not_up_mig_cap = 1,
    Tos_not_present_mp = 2,
  };

  enum Psci_affinity_info
  {
    Aff_info_on         = 0,
    Aff_info_off        = 1,
    Aff_info_on_pending = 2,
  };

  inline l4_mword_t affinity(l4_mword_t reg, bool smccc_64)
  {
    if ((sizeof(reg) == 4) || smccc_64)
      return reg;

    l4_uint32_t aff3_mask_32 = 0xffU << 24;

    // Delete [63-32] by applying a 32bit mask
    // Move aff3 from [31-24] to [39-32]
    return ((reg & aff3_mask_32) << 8) | (reg & ~aff3_mask_32);
  }

public:
  Psci_device(Vmm::Guest *vmm, cxx::Ref_ptr<Vmm::Pm> pm,
              cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus)
  : _vmm(vmm),
    _pm(pm),
    _cpus(cpus)
  {}

  bool vm_call(unsigned imm, Vmm::Vcpu_ptr vcpu) override
  {
    if (imm != 0)
      return false;

    // Check this is a supported PSCI function call id.
    if (!is_valid_func_id(vcpu->r.r[0]))
      return false;

    l4_uint8_t func = vcpu->r.r[0] & 0x1f;
    switch (func)
      {
      case Psci_version:
        vcpu->r.r[0] = 0x00010000; // v1.0
        break;
      case Cpu_suspend:
        psci_cpu_suspend(vcpu);
        break;
      case Cpu_off:
        psci_cpu_off(vcpu);
        break;
      case Cpu_on:
        psci_cpu_on(vcpu);
        break;
      case Affinity_info:
        psci_affinity_info(vcpu);
        break;
      case Migrate_info_type:
        vcpu->r.r[0] = Tos_not_present_mp;
        break;
      case System_off:
        _vmm->shutdown(Vmm::Guest::Shutdown);
        break;
      case System_reset:
        _vmm->shutdown(Vmm::Guest::Reboot);
        break;
      case Psci_features:
        psci_features(vcpu);
       break;
      case System_suspend:
        psci_system_suspend(vcpu);
        break;
      default:
        warn.printf("... Not supported PSCI function 0x%x called\n",
                    static_cast<unsigned>(func));
        vcpu->r.r[0] = Not_supported;
        break;
      };

    return true;
  }

private:
  void psci_cpu_suspend(Vmm::Vcpu_ptr vcpu)
  {
    /*
     * Ignore the power state. We do not implement any special behavior for low-
     * power, but behave the same like in the non low-power case. According to
     * the PSCI spec. section 5.4.5 point 3. it is allowed for the PSCI
     * implementer to downgrade to a standby state. In this case we just return
     * from this function without jumping to the entry_point_address.
     */
    _vmm->wait_for_timer_or_irq(vcpu);

    vcpu->r.r[0] = Success;
  }

  void psci_cpu_off(Vmm::Vcpu_ptr vcpu)
  {
    Vmm::Cpu_dev *target = current_cpu();
    target->stop();
    // should never return
    vcpu->r.r[0] = Internal_failure;
  }

  void psci_cpu_on(Vmm::Vcpu_ptr vcpu)
  {
    l4_mword_t hwid = affinity(vcpu->r.r[1], is_64bit_call(vcpu->r.r[0]));
    Vmm::Cpu_dev *target = lookup_cpu(hwid);

    if (target)
      {
        // XXX There is currently no way to detect error conditions like
        // INVALID_ADDRESS
        if (!target->online() && target->mark_on_pending())
          {
            l4_mword_t ip = vcpu->r.r[2];
            l4_mword_t context =  vcpu->r.r[3];
            target->vcpu()->r.r[0] = context;
            _vmm->prepare_vcpu_startup(target->vcpu(), ip);
            if (target->start_vcpu())
              vcpu->r.r[0] = Success;
            else
              vcpu->r.r[0] = Internal_failure;
          }
        else
          vcpu->r.r[0] = target->online_state() == Vmm::Cpu_dev::Cpu_state::On
            ? Already_on : On_pending;
      }
    else
      vcpu->r.r[0] = Invalid_parameters;
  }

  void psci_affinity_info(Vmm::Vcpu_ptr vcpu)
  {
    // parameters:
    // * target_affinity
    // * lowest affinity level
    l4_mword_t hwid = affinity(vcpu->r.r[1], is_64bit_call(vcpu->r.r[0]));
    l4_umword_t lvl = vcpu->r.r[2];

    // Default to invalid in case we do not find a matching CPU
    vcpu->r.r[0] = Invalid_parameters;

    // There are at most 3 affinity levels
    if (lvl > 3)
      return;

    for (auto const &cpu : *_cpus.get())
      if (cpu && cpu->matches(hwid, lvl))
        {
          if (cpu->online())
            {
              vcpu->r.r[0] = Aff_info_on;
              return;
            }
          vcpu->r.r[0] = Aff_info_off;
        }
  }

  void psci_features(Vmm::Vcpu_ptr vcpu)
  {
    // Check this uses an allowed SMCCC bitness and is a valid PSCI
    // function id.
    if (!(   is_valid_call(vcpu->r.r[1])
          && is_valid_func_id(vcpu->r.r[1])))
      {
        vcpu->r.r[0] = Not_supported;
        return;
      }

    l4_uint8_t feat_func = vcpu->r.r[1] & 0x1f;
    switch (feat_func)
      {
      case Cpu_suspend:
        vcpu->r.r[0] = 1 << 1;
        break;
      case Psci_version:
      case Cpu_on:
      case Cpu_off:
      case Affinity_info:
      case Migrate_info_type:
      case System_off:
      case System_reset:
      case Psci_features:
      case System_suspend:
        vcpu->r.r[0] = Success;
        break;
      default:
        vcpu->r.r[0] = Not_supported;
        break;
      };
  }

  void psci_system_suspend(Vmm::Vcpu_ptr vcpu)
  {
    l4_addr_t entry_gpa = vcpu->r.r[1];
    l4_umword_t context_id = vcpu->r.r[2];

    // Check preconditions:
    //   * Request has to be executed on CPU0 (requirement imposed
    //     by us)
    //   * all other CPUs have to be off (specification requirement)
    //   * powermanagement allows suspend operation
    if (    current_cpu()->vcpu().get_vcpu_id() != 0
        || !cpus_off() || !_pm->suspend())
      {
        vcpu->r.r[0] = Denied;
        return;
      }

    /* Go to sleep */
    vcpu.wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
    /* Back alive */
    _pm->resume();

    memset(&vcpu->r, 0, sizeof(vcpu->r));
    _vmm->prepare_vcpu_startup(vcpu, entry_gpa);
    vcpu->r.r[0]  = context_id;
    l4_vcpu_e_write_32(*vcpu, L4_VCPU_E_SCTLR,
        l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR) & ~1U);
  }

  Vmm::Cpu_dev *current_cpu() const
  { return _cpus->cpu(vmm_current_cpu_id).get(); }

  Vmm::Cpu_dev *lookup_cpu(l4_umword_t hwid) const
  {
    for (auto const &cpu : *_cpus.get())
      if (cpu && cpu->matches(hwid))
        return cpu.get();

    return nullptr;
  }

  bool cpus_off() const
  {
    bool first = true;
    for (auto const &cpu : *_cpus.get())
      {
        // ignore boot cpu
        if (first)
          {
            first = false;
            continue;
          }

        if (cpu && cpu->online())
          return false;
      }

    return true;
  }

  bool is_valid_func_id(l4_umword_t reg) const
  {
    // Check for the correct SMC calling convention:
    // - this must be a fast call (bit 31)
    // - it is within the Standard Secure Service range (bits 29:24)
    // - it is within the PSCI range (bits 4:0)
    // - the rest must be zero
    return (reg & 0xbfffffe0) == 0x84000000;
  }

  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Pm> _pm;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
};

struct F : Factory
{
  cxx::Ref_ptr<Device> create(Vdev::Device_lookup *devs,
                              Dt_node const &node) override
  {
    auto c = make_device<Psci_device>(devs->vmm(), devs->pm(), devs->cpus());
    Vmm::Guest::Smccc_method smccc_method = Vmm::Guest::Hvc;

    char const *method = node.get_prop<char>("method", nullptr);
    if (method)
      {
        if (strcmp(method, "smc") == 0)
          smccc_method = Vmm::Guest::Smc;
        else if (strcmp(method, "hvc") != 0)
          warn.printf("Method '%s' is not supported. Must be hvc or smc!\n",
                      method);
      }

    info.printf("Register PSCI device: %s mode\n",
                smccc_method == Vmm::Guest::Hvc ? "hvc" : "smc");

    devs->vmm()->register_vm_handler(smccc_method, c);

    return c;
  }
};

static F f;
static Device_type t1 = { "arm,psci", nullptr, &f };
static Device_type t2 = { "arm,psci-0.2", nullptr, &f };
static Device_type t3 = { "arm,psci-1.0", nullptr, &f };
}
