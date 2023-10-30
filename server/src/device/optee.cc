/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2020 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 */
#include <l4/re/env>
#include <l4/sys/arm_smccc>

#include "device_factory.h"
#include "ds_mmio_mapper.h"
#include "guest.h"
#include "irq_dt.h"
#include "irq_svr.h"
#include "smccc_device.h"

namespace {

Dbg info(Dbg::Dev, Dbg::Info, "optee");
Dbg warn(Dbg::Dev, Dbg::Warn, "optee");
Dbg trace(Dbg::Dev, Dbg::Warn, "optee");

/**
 * Provides an interface to the OP-TEE secure OS.
 *
 * The device maps the static shared memory to the appropriate address
 * that is advertised by the SMC interface and forwards any trapped SMC
 * via IPC.
 *
 * A device tree entry needs to look like this:
 *
 *     firmware {
 *       optee {
 *         compatible = "linaro,optee-tz";
 *         method = "smc";
 *         l4vmm,cap = "smccc";
 *         l4vmm,dscap = "vbus";
 *         interrupts = <0 140 4>;
 *       };
 *     };
 *
 * `l4vmm,cap` is mandatory and needs to point to a capability providing
 * an L4::Arm_smccc interface. If there is no capability with the given name
 * the device will be disabled.
 *
 * The optional `l4vmm,dscap` may point to an alternative provider of the
 * static shared memory. If omitted, memory will be mapped from `l4vmm,cap`.
 *
 * To give direct access to Optee to a VM, set `l4vmm,cap` to the smccc
 * capability provided by Fiasco and point `l4vmm,dscap` to an appropriately
 * configured IO. When using a proxy, set `l4vmm,cap` only.
 */
class Optee : public Vdev::Device, public Vmm::Smccc_device
{
  enum
  {
    Smc_call_trusted_os_uid      = 0xbf00ff01,
    Smc_call_trusted_os_revision = 0xbf00ff03,
    Optee_call_get_shm_config    = 0xb2000007,
    Optee_call_exchange_caps     = 0xb2000009,

    Optee_uuid_word0 = 0x384fb3e0,
    Optee_uuid_word1 = 0xe7f811e3,
    Optee_uuid_word2 = 0xaf630002,
    Optee_uuid_word3 = 0xa5d5c51b,

    Optee_api_major = 2,
    Optee_api_minor = 0
  };

public:
  Optee(L4::Cap<L4::Arm_smccc> optee) : _optee(optee) {}

  bool vm_call(unsigned imm, Vmm::Vcpu_ptr vcpu) override
  {
    if (imm != 0)
      return false;

    if (   _optee.is_valid()
        && is_valid_func_id(vcpu->r.r[0]))
      {
        _optee->call(vcpu->r.r[0], vcpu->r.r[1], vcpu->r.r[2], vcpu->r.r[3],
                     vcpu->r.r[4], vcpu->r.r[5], vcpu->r.r[6],
                     &vcpu->r.r[0], &vcpu->r.r[1], &vcpu->r.r[2], &vcpu->r.r[3], 0);
        return true;
      }
    return false;
  }

  int map_optee_memory(Vmm::Guest *vmm, L4::Cap<L4Re::Dataspace> iods)
  {
    l4_umword_t p[4];

    // check for OP-TEE OS
    long ret = fast_call(Smc_call_trusted_os_uid, p);

    if (ret < 0 || p[0] != Optee_uuid_word0 || p[1] != Optee_uuid_word1 ||
        p[2] != Optee_uuid_word2 || p[3] != Optee_uuid_word3)
      {
        warn.printf("OP-TEE not running.\n");
        return -L4_ENODEV;
      }

    // check for correct API version
    ret = fast_call(Smc_call_trusted_os_revision, p);

    if (ret < 0 || p[0] != Optee_api_major || p[1] != Optee_api_minor)
      {
        warn.printf("OP-TEE has wrong API (%ld.%ld). Need %x.%x.\n",
                    p[0], p[1], Optee_api_major, Optee_api_minor);
        return -L4_EINVAL;
      }

    // check if OP-TEE exports memory
    ret = fast_call(Optee_call_exchange_caps, p);

    if (ret < 0 || p[0] != 0 || !(p[1] & 1))
      {
        warn.printf("OP-TEE does not export shared memory.\n");
        return -L4_ENODEV;
      }

    // get the memory area
    ret = fast_call(Optee_call_get_shm_config, p);

    if (ret < 0 || p[0] != 0)
      {
        warn.printf("Failed to get shared memory configuration.\n");
        return -L4_ENODEV;
      }

    trace.printf("OP-TEE start = 0x%lx  size = 0x%lx\n", p[1], p[2]);
    auto handler = Vdev::make_device<Ds_handler>(
        cxx::make_ref_obj<Vmm::Ds_manager>("Optee", iods, p[1], p[2])
      );
    // XXX should check that the resource is actually available
    vmm->add_mmio_device(Vmm::Region(Vmm::Guest_addr(p[1]),
                                     Vmm::Guest_addr(p[1] + p[2] - 1),
                                     Vmm::Region_type::Virtual), handler);

    return L4_EOK;
  }

  void set_notification_irq(cxx::Ref_ptr<Vdev::Irq_svr> &&irq)
  { _irq = std::move(irq); }

private:
  long fast_call(l4_umword_t func, l4_umword_t out[])
  {
    return l4_error(_optee->call(func, 0, 0, 0, 0, 0, 0,
                                 out, out + 1, out + 2, out + 3, 0));
  }

  bool is_valid_func_id(l4_umword_t reg) const
  {
    // Check this is in the trusted application/OS range
    reg &= 0x3f00ffff;
    return (reg >= 0x30000000 && reg <= 0x3f00ffff);
  }

  L4::Cap<L4::Arm_smccc> _optee;
  cxx::Ref_ptr<Vdev::Irq_svr> _irq;
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    info.printf("Create OP-TEE device\n");

    auto cap = Vdev::get_cap<L4::Arm_smccc>(node, "l4vmm,cap");
    if (!cap)
      return nullptr;

    auto dscap = Vdev::get_cap<L4Re::Dataspace>(node, "l4vmm,dscap", cap);
    if (!dscap)
      return nullptr;

    auto c = Vdev::make_device<Optee>(cap);
    if (c->map_optee_memory(devs->vmm(), dscap) < 0)
      return nullptr;

    Vdev::Irq_dt_iterator it(devs, node);

    if (it.next(devs) >= 0)
      {
        auto icu = L4::cap_dynamic_cast<L4::Icu>(cap);

        if (icu)
          {
            if (!it.ic_is_virt())
              L4Re::chksys(-L4_EINVAL, "OP-TEE device requires a virtual interrupt controller");

            // XXX Using a standard IO interrupt here. Possibly better to
            // write our own non-masking irq svr.
            auto irq_svr =
              cxx::make_ref_obj<Vdev::Irq_svr>(devs->vmm()->registry(), icu, 0,
                                               it.ic(), it.irq());

            c->set_notification_irq(std::move(irq_svr));
          }
        else
          // When no proxy is used, there is also no notification available.
          // So it is not necessarily an error, when no ICU can be found.
          warn.printf("SMC device does not support notification interrupts.\n");
      }

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

    info.printf("Register OP-TEE device: %s mode\n",
                smccc_method == Vmm::Guest::Hvc ? "hvc" : "smc");

    devs->vmm()->register_vm_handler(smccc_method, c);

    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "linaro,optee-tz", nullptr, &f };
