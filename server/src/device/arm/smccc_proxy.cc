/*
 * Copyright (C) 2025 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/re/env>
#include <l4/sys/meta>
#include <l4/sys/arm_smccc>

#include "device_factory.h"
#include "smccc_device.h"
#include "guest.h"

/**
 * Forwards smccc calls from the guest to an external entity. This proxy does
 * not do any filtering, so it is the responsibility of the external entity to
 * do this.
 *
 * Configure this device using the following device tree node adapted to your
 * platform needs.
 *
 * \code{.dtb}
 *   smccc_proxy {
 *       compatible = "l4vmm,smccc_proxy";
 *       l4vmm,smccc_cap = "smc";
 *       method = "smc";
 *   };
 * \endcode
 *
 * The default cap name for l4vmm,smccc_cap is "smc". Method can be "smc" or
 * "hvc".
 */

static Dbg warn(Dbg::Dev, Dbg::Warn, "smccc_proxy");

namespace {

using namespace Vdev;

class Smccc_proxy : public Device, public Vmm::Smccc_device
{
public:
  Smccc_proxy(L4::Cap<L4::Arm_smccc> smc)
  : _smc(smc)
  {}

  bool vm_call(unsigned imm, Vmm::Vcpu_ptr vcpu) override
  {
    if (imm != 0)
      return false;

    _smc->call(vcpu->r.r[0], vcpu->r.r[1], vcpu->r.r[2], vcpu->r.r[3],
               vcpu->r.r[4], vcpu->r.r[5], vcpu->r.r[6],
               &vcpu->r.r[0], &vcpu->r.r[1], &vcpu->r.r[2], &vcpu->r.r[3], 0);

    return true;
  }

private:
  L4Re::Util::Unique_cap<L4::Arm_smccc> _smc;
};

class F : public Factory
{
public:
  cxx::Ref_ptr<Device> create(Device_lookup *devs,
                              Dt_node const &node) override
  {
    warn.printf("smccc_proxy\n");

    auto smc = Vdev::get_cap<L4::Arm_smccc>(node, "l4vmm,smccc_cap",
                 L4Re::Env::env()->get_cap<L4::Arm_smccc>("smc"));
    if (!smc)
      return nullptr;

    Vmm::Guest::Smccc_method smccc_method = Vmm::Guest::Smc;

    char const *method = node.get_prop<char>("method", nullptr);
    if (method)
      {
        if (strcmp(method, "hvc") == 0)
          smccc_method = Vmm::Guest::Hvc;
        else if (strcmp(method, "smc") != 0)
          warn.printf("Method '%s' is not supported. Must be hvc or smc!\n",
                      method);
      }

    auto c = Vdev::make_device<Smccc_proxy>(smc);

    devs->vmm()->register_vm_handler(smccc_method, c);

    return c;
  }
};

static F f;
static Device_type t1 = { "l4vmm,smccc_proxy", nullptr, &f };

}
