/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "cpu_dev_array.h"
#include "device.h"
#include "device_repo.h"
#include "guest.h"
#include "vm_ram.h"
#include "virt_bus.h"

namespace Vmm {

/**
 * The main instance of a hardware-virtualized guest.
 */
class Vm : public Vdev::Device_lookup
{
public:
  cxx::Ref_ptr<Vdev::Device>
  device_from_node(Vdev::Dt_node const &node) const override
  { return _devices.device_from_node(node); }

  Vmm::Guest *vmm() const override
  { return _vmm; }

  cxx::Ref_ptr<Vmm::Vm_ram> ram() const override
  { return _ram; }

  cxx::Ref_ptr<Vmm::Virt_bus> vbus() const override
  { return _vbus; }

  cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const override
  { return _cpus; }

  /**
   * \see Device_lookup::get_or_create_ic_dev(Vdev::Dt_node const &node,
   *                                          bool fatal)
   */
  cxx::Ref_ptr<Gic::Ic> get_or_create_ic_dev(Vdev::Dt_node const &node,
                                             bool fatal) override;
  /**
   * \see Device_lookup::get_or_create_ic(Vdev::Dt_node const &node,
   *                                      cxx::Ref_ptr<Gic::Ic> *ic_ptr)
   */
  Ic_error get_or_create_ic(Vdev::Dt_node const &node,
                            cxx::Ref_ptr<Gic::Ic> *ic_ptr) override;

  void create_default_devices(l4_addr_t rambase)
  {
    _vmm = Vmm::Guest::create_instance();
    _ram = Vdev::make_device<Vmm::Vm_ram>(rambase, Vmm::Guest::Boot_offset,
                                          _vmm->memmap());

    auto vbus_cap = L4Re::Env::env()->get_cap<L4vbus::Vbus>("vbus");
    _vbus = cxx::make_ref_obj<Vmm::Virt_bus>(vbus_cap);

    _cpus = Vdev::make_device<Vmm::Cpu_dev_array>();
  }

  void add_device(Vdev::Dt_node const &node,
                  cxx::Ref_ptr<Vdev::Device> dev) override
  { _devices.add(node, dev); }

private:
  Vdev::Device_repository _devices;
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
};
}
