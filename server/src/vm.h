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
#include "ram_ds.h"
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

  cxx::Ref_ptr<Vmm::Ram_ds> ram() const override
  { return _ram; }

  cxx::Ref_ptr<Vmm::Virt_bus> vbus() const override
  { return _vbus; }

  cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const override
  { return _cpus; }

  void create_default_devices(l4_addr_t rambase)
  {
    _vmm = Vmm::Guest::create_instance();

    L4Re::Env const *e = L4Re::Env::env();

    auto ram = L4Re::chkcap(e->get_cap<L4Re::Dataspace>("ram"),
                            "ram dataspace cap", -L4_ENOENT);
    _ram = Vdev::make_device<Vmm::Ram_ds>(ram, rambase,
                                          Vmm::Guest::Boot_offset);
    _vmm->add_mmio_device(Region::ss(_ram->vm_start(), _ram->size()),
                          Vdev::make_device<Ds_handler>(_ram->ram(),
                                                        _ram->local_start(),
                                                        _ram->size()));

    auto vbus_cap = e->get_cap<L4vbus::Vbus>("vbus");
    if (!vbus_cap)
      vbus_cap = e->get_cap<L4vbus::Vbus>("vm_bus");
    _vbus = cxx::make_ref_obj<Vmm::Virt_bus>(vbus_cap);

    _cpus = Vdev::make_device<Vmm::Cpu_dev_array>();
  }

  void add_device(Vdev::Dt_node const &node,
                  cxx::Ref_ptr<Vdev::Device> dev)
  { _devices.add(node, dev); }

  void init_devices(Vdev::Device_tree dt)
  { _devices.init_devices(this, dt); }

private:
  Vdev::Device_repository _devices;
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Ram_ds> _ram;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
};

}
