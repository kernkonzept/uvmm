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
#include "msi_controller.h"

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

cxx::Ref_ptr<Gic::Msi_controller>
Vm::get_or_create_mc_dev(Vdev::Dt_node const &node)
{
  Vdev::Dt_node msi_parent = find_msi_parent(node);

  if (!msi_parent.is_valid())
    L4Re::chksys(-L4_EINVAL, "Node has an MSI parent.");

  if (!Vdev::Factory::is_vdev(msi_parent))
    L4Re::chksys(-L4_EINVAL, "MSI parent node is a device.");

  auto dev = Vdev::Factory::create_dev(this, msi_parent);
  auto msi_ctlr = cxx::dynamic_pointer_cast<Gic::Msi_controller>(dev);

  if (!msi_ctlr)
    L4Re::chksys(-L4_EINVAL, "MSI controller is the MSI parent of the device.");

  return msi_ctlr;
}

}
