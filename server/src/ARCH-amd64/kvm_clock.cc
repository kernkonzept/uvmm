/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2020, 2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#include "device_factory.h"
#include "guest.h"
#include "kvm_clock.h"
#include "mem_types.h"

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                    Vdev::Dt_node const &) override
  {
    auto dev = Vdev::make_device<Vdev::Kvm_clock_ctrl>(devs->ram(),
                                                       devs->vmm());

    devs->vmm()->register_msr_device(dev);
    devs->vmm()->register_cpuid_device(dev);

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"kvm-clock", nullptr, &f};

} // namespace
