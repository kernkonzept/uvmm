/*
 * Copyright (C) 2017-2021 Kernkonzept GmbH.
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
#include "monitor/vm_cmd_handler.h"
#include "pm.h"

namespace Vmm {

/**
 * The main instance of a hardware-virtualized guest.
 */
class Vm
: public Vdev::Device_lookup,
  public Monitor::Vm_cmd_handler<Monitor::Enabled, Vm>
{
  friend Vm_cmd_handler<Monitor::Enabled, Vm>;

public:
  cxx::Ref_ptr<Vdev::Device>
  device_from_node(Vdev::Dt_node const &node,
                   std::string *path = nullptr) const override
  { return _devices.device_from_node(node, path); }

  Vmm::Guest *vmm() const override
  { return _vmm; }

  cxx::Ref_ptr<Vmm::Vm_ram> ram() const override
  { return _ram; }

  cxx::Ref_ptr<Vmm::Virt_bus> vbus() const override
  { return _vbus; }

  cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus() const override
  { return _cpus; }

  cxx::Ref_ptr<Vmm::Pm> pm() const override
  { return _pm; }

  /**
   * \see Device_lookup::get_or_create_ic(Vdev::Dt_node const &node,
   *                                      cxx::Ref_ptr<Gic::Ic> *ic_ptr)
   */
  Ic_error get_or_create_ic(Vdev::Dt_node const &node,
                            cxx::Ref_ptr<Gic::Ic> *ic_ptr) override;

  /**
   * \see Device_lookup::get_or_create_mc(
   *        Vdev::Dt_node const &node,
   *        cxx::Ref_ptr<Gic::Msix_controller> *mc_ptr)
   */
  Mc_error
  get_or_create_mc(Vdev::Dt_node const &node,
                   cxx::Ref_ptr<Gic::Msix_controller> *mc_ptr) override;

  /**
   * \see Device_lookup::get_or_create_mc_dev()
   */
  cxx::Ref_ptr<Gic::Msix_controller>
  get_or_create_mc_dev(Vdev::Dt_node const &node) override;

  void create_default_devices()
  {
    _vmm = Vmm::Guest::create_instance();
    _ram = Vdev::make_device<Vmm::Vm_ram>(Vmm::Guest::Boot_offset);

    auto vbus_cap = L4Re::Env::env()->get_cap<L4vbus::Vbus>("vbus");
    _vbus = Vdev::make_device<Vmm::Virt_bus>(vbus_cap, _vmm->registry());

    _cpus = Vdev::make_device<Vmm::Cpu_dev_array>();

    _pm = Vdev::make_device<Vmm::Pm>();

  }

  void add_device(Vdev::Dt_node const &node,
                  cxx::Ref_ptr<Vdev::Device> dev,
                  std::string const &path = std::string()) override
  { _devices.add(node, dev, path); }

  /**
   * Find MSI parent of node.
   *
   * \param node  Node to find the MSI parent of.
   *
   * \return  The node of the MSI parent or an invalid node, if neither the
   *          'msi-parent' nor the 'msi-map' property are specified or
   *          reference an invalid node.
   *
   * \note  Currently, this function only returns the simple case of one
   *        referenced MSI parent node in the device tree.
   */
  Vdev::Dt_node find_msi_parent(Vdev::Dt_node const &node) const
  {
    int size = 0;
    auto *prop = node.get_prop<fdt32_t>("msi-parent", &size);
    if (prop)
      {
        if (size != 1)
          L4Re::throw_error(
            -L4_EINVAL, "The msi-parent property must be a single reference.");

        return node.find_phandle(*prop);
      }

    prop = node.get_prop<fdt32_t>("msi-map", &size);
    if (prop)
      {
        if (size != 4)
          L4Re::throw_error(
            -L4_EINVAL, "The msi-map property must contain exactly one entry.");

        return node.find_phandle(prop[1]);
      }

    return Vdev::Dt_node();
  }

  /**
   * Collect and instantiate all devices described in the device tree.
   *
   * \param dt  Device tree to scan.
   *
   * This function first instantiates all device for which a virtual
   * implementation exists and then goes through the remaining devices
   * and tries to assign any missing resources from the vbus (if existing).
   */
  void scan_device_tree(Vdev::Device_tree dt);

private:
  bool add_virt_device(Vdev::Dt_node const &node);
  bool add_phys_device(Vdev::Dt_node const &node);
  bool add_phys_device_by_vbus_id(Vdev::Dt_node const &node);

  Vdev::Device_repository _devices;
  Vmm::Guest *_vmm;
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
  cxx::Ref_ptr<Vmm::Virt_bus> _vbus;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
  cxx::Ref_ptr<Vmm::Pm> _pm;
};
}
