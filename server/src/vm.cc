/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Jean Wolter <jean.wolter@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "vm.h"
#include "device.h"
#include "device_factory.h"
#include "debug.h"
#include "io_proxy.h"
#include "msi_controller.h"

static Dbg warn(Dbg::Core, Dbg::Warn, "vm");

namespace Vmm {

Vdev::Device_lookup::Ic_error
Vm::get_or_create_ic(Vdev::Dt_node const &node, cxx::Ref_ptr<Gic::Ic> *ic_ptr)
{
  Vdev::Dt_node ic_node = node.find_irq_parent();
  if (!ic_node.is_valid())
    return Ic_e_no_iparent;

  if (!ic_node.is_enabled())
    return Ic_e_disabled;

  if (!Vdev::Factory::is_vdev(ic_node))
    return Ic_e_no_virtic;

  cxx::Ref_ptr<Vdev::Device> dev = device_from_node(ic_node);
  if (!dev)
    {
      if (!Vdev::Factory::create_irq_parent(this, node))
        return Ic_e_failed;

      dev = device_from_node(ic_node);
      assert(dev);
    }

  cxx::Ref_ptr<Gic::Ic> ic = cxx::dynamic_pointer_cast<Gic::Ic>(dev);
  if (!ic)
    return Ic_e_no_virtic;

  *ic_ptr = ic;
  return Ic_ok;
}

cxx::Ref_ptr<Gic::Ic>
Vm::get_or_create_ic_dev(Vdev::Dt_node const &node, bool fatal)
{
  cxx::Ref_ptr<Gic::Ic> ic;
  Ic_error res = get_or_create_ic(node, &ic);
  if (res == Ic_ok)
    return ic;

  Dbg(Dbg::Dev, Dbg::Info).printf("%s: Failed to get interrupt parent: %s\n",
                                  node.get_name(), ic_err_str(res));

  if (fatal)
    L4Re::chksys(-L4_ENODEV, "Unable to locate interrupt parent");

  return nullptr;
}

cxx::Ref_ptr<Gic::Msix_controller>
Vm::get_or_create_mc_dev(Vdev::Dt_node const &node)
{
  Vdev::Dt_node msi_parent = find_msi_parent(node);

  if (!msi_parent.is_valid())
    L4Re::chksys(-L4_EINVAL, "Node has an MSI parent.");

  if (!Vdev::Factory::is_vdev(msi_parent))
    L4Re::chksys(-L4_EINVAL, "MSI parent node is a device.");

  auto dev = Vdev::Factory::create_dev(this, msi_parent);
  auto msi_ctlr = cxx::dynamic_pointer_cast<Gic::Msix_controller>(dev);

  if (!msi_ctlr)
    L4Re::chksys(-L4_EINVAL, "MSI controller is the MSI parent of the device.");

  return msi_ctlr;
}

void
Vm::scan_device_tree(Vdev::Device_tree dt)
{
  vmm()->setup_device_tree(dt);

  // Instantiate all virtual devices
  dt.scan([this] (Vdev::Dt_node const &node, unsigned /* depth */)
          { return add_virt_device(node); },
          [] (Vdev::Dt_node const &, unsigned) {});

  // Instantiate physical devices that request a specific vbus device
  dt.scan([this] (Vdev::Dt_node const &node, unsigned /* depth */)
          { return add_phys_device_by_vbus_id(node); },
          [] (Vdev::Dt_node const &, unsigned) {});

  // Prepare creation of physical devices
  Vdev::Io_proxy::prepare_factory(this);

  // Instantiate all devices which have the necessary resources
  dt.scan([this] (Vdev::Dt_node const &node, unsigned /* depth */)
          { return add_phys_device(node); },
          [] (Vdev::Dt_node const &, unsigned) {});
}

bool
Vm::add_virt_device(Vdev::Dt_node const &node)
{
  // Ignore non virtual devices
  if (!Vdev::Factory::is_vdev(node))
    return true;

  if (Vdev::Factory::create_dev(this, node))
    return true;

  warn.printf("Device creation for virtual device %s failed. Disabling device.\n",
              node.get_name());

  node.setprop_string("status", "disabled");

  return false;
}

bool
Vm::add_phys_device(Vdev::Dt_node const &node)
{
  // device_type is a deprecated option and should be set for "cpu"
  // and "memory" devices only. Currently there are some more uses
  // like "pci", "network", "phy", "soc2, "mdio", but we ignore these
  // here, since they do not need special treatment.
  char const *devtype = node.get_prop<char>("device_type", nullptr);

  // Ignore memory nodes
  if (devtype && strcmp("memory", devtype) == 0)
    {
      // there should be no subnode to memory devices so it should be
      // safe to return false to stop traversal of subnodes
      return false;
    }

  cxx::Ref_ptr<Vdev::Device> dev;
  bool is_cpu_dev = devtype && strcmp("cpu", devtype) == 0;

  // Cpu devices need to be treated specially because they use a
  // different factory (there are too many compatible attributes to
  // use the normal factory mechanism).
  if (is_cpu_dev)
    {
      dev = cpus()->create_vcpu(&node);
      if (!dev)
        return false;

      // XXX Other create methods directly add the created device to the device
      // repository; We might want to do the same in create_vcpu.
      add_device(node, dev);
      return true;
    }
  else
    {
      if (!node.has_irqs() && !node.has_mmio_regs())
        return true;

      if (Vdev::Factory::create_dev(this, node))
        return true;
    }

  // Device creation failed
  if (node.has_prop("l4vmm,force-enable"))
    {
      warn.printf("Device creation for %s failed, 'l4vmm,force-enable' set\n",
                  node.get_name());
      return true;
    }

  warn.printf("Device creation for %s failed. Disabling device.\n",
              node.get_name());

  node.setprop_string("status", "disabled");
  return false;
}

bool
Vm::add_phys_device_by_vbus_id(Vdev::Dt_node const &node)
{
  if (!node.has_irqs() && !node.has_mmio_regs())
    return true;

  if (!node.has_prop("l4vmm,vbus-dev"))
    return true;

  if (Vdev::Factory::create_dev(this, node))
    return true;

  warn.printf("Device creation for %s failed. Disabling device.\n",
              node.get_name());

  node.setprop_string("status", "disabled");
  return false;
}

}
