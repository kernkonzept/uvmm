/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/env>
#include <l4/sys/arm_smccc>

#include "device_factory.h"
#include "ds_mmio_mapper.h"
#include "guest.h"
#include "io_proxy.h"
#include "smc_device.h"

namespace {

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
 *         method = "smccc";
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
class Optee : public Vdev::Device, public Vmm::Smc_device
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

  void smc(Vmm::Vcpu_ptr vcpu) override
  {
    if (_optee.is_valid())
      _optee->call(vcpu->r.r[0], vcpu->r.r[1], vcpu->r.r[2], vcpu->r.r[3],
                   vcpu->r.r[4], vcpu->r.r[5], vcpu->r.r[6],
                   &vcpu->r.r[0], &vcpu->r.r[1], &vcpu->r.r[2], &vcpu->r.r[3], 0);
  }

  int map_optee_memory(Vmm::Guest *vmm, L4::Cap<L4Re::Dataspace> iods)
  {
    l4_umword_t p[4];

    // check for OP-TEE OS
    long ret = fast_call(Smc_call_trusted_os_uid, p);

    if (ret < 0 || p[0] != Optee_uuid_word0 || p[1] != Optee_uuid_word1 ||
        p[2] != Optee_uuid_word2 || p[3] != Optee_uuid_word3)
      {
        warn.printf("OP-TEE not runing.\n");
        return -L4_ENODEV;
      }

    // check for correct API version
    ret = fast_call(0xbf00ff03, p);

    if (ret < 0 || p[0] != Optee_api_major || p[1] != Optee_api_minor)
      {
        warn.printf("OP-TEE has wrong API (%ld.%ld). Need 2.0.\n",
                    p[0], p[1]);
        return -L4_EINVAL;
      }

    // check if the OS exports memory
    ret = fast_call(0xb2000009, p);

    if (ret < 0 || p[0] != 0 || !(p[1] & 1))
      {
        warn.printf("OP-TEE does not export shared memory.\n");
        return -L4_ENODEV;
      }

    // get the memory area
    ret = fast_call(0xb2000007, p);

    if (ret < 0 || p[0] != 0)
      {
        warn.printf("Failed to get shared memory configuration.\n");
        return -L4_ENODEV;
      }

    trace.printf("OP-TEE start = 0x%lx  size = 0x%lx\n", p[1], p[2]);
    auto handler = Vdev::make_device<Ds_handler>(iods, 0, p[2], p[1]);
    // XXX should check that the resource is actually available
    vmm->add_mmio_device(Region(p[1], p[1] + p[2] - 1), handler);

    return L4_EOK;
  }

private:
  long fast_call(l4_umword_t func, l4_umword_t out[])
  {
    return l4_error(_optee->call(func, 0, 0, 0, 0, 0, 0,
                                 out, out + 1, out + 2, out + 3, 0));
  }

  L4::Cap<L4::Arm_smccc> _optee;
};

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Dbg(Dbg::Dev, Dbg::Info).printf("Create OP-TEE device\n");

    int cap_name_len;

    char const *cap_name = node.get_prop<char>("l4vmm,cap", &cap_name_len);
    if (!cap_name)
      {
        warn.printf("l4vmm,cap property missing for OP-TEE device.\n");
        return nullptr;
      }

    auto cap = L4Re::Env::env()->get_cap<L4::Arm_smccc>(cap_name);
    if (!cap.is_valid())
      {
        warn.printf("'l4vmm,cap' property: capability '%.*s' is invalid.\n",
                    cap_name_len, cap_name);
        return nullptr;
      }

    auto c = Vdev::make_device<Optee>(cap);

    L4::Cap<L4Re::Dataspace> dscap;
    cap_name = node.get_prop<char>("l4vmm,dscap", &cap_name_len);

    if (cap_name)
      {
        dscap = L4Re::Env::env()->get_cap<L4Re::Dataspace>(cap_name);
        if (!dscap.is_valid())
          {
            warn.printf("'l4vmm,dscap' property: capability '%.*s' is invalid.\n",
                        cap_name_len, cap_name);
            return nullptr;
          }
      }
    else
      dscap = L4::cap_reinterpret_cast<L4Re::Dataspace>(cap);

    if (c->map_optee_memory(devs->vmm(), dscap) < 0)
      return nullptr;

    auto ic = devs->get_or_create_ic_dev(node, false);

    if (ic && ic->dt_get_num_interrupts(node) > 0)
      {
        // XXX Using a standard IO interrupt here. Possibly better to
        // write our own non-masking irq svr.
        auto irq_svr = Vdev::make_device<Vdev::Irq_svr>(0);

        L4Re::chkcap(devs->vmm()->registry()->register_irq_obj(irq_svr.get()),
            "Register IRQ handling server.");

        auto icu = L4::cap_dynamic_cast<L4::Icu>(cap);
        L4Re::chksys(icu->bind(0, irq_svr->obj_cap()),
            "Bind to IRQ to OP-TEE service.");

        unsigned dt_irq = ic->dt_get_interrupt(node, 0);

        irq_svr->set_sink(ic.get(), dt_irq);
        ic->bind_irq_source(dt_irq, irq_svr);
      }

    devs->vmm()->register_smc_handler(c);

    return c;
  }
};

}

static F f;
static Vdev::Device_type t = { "linaro,optee-tz", nullptr, &f };
