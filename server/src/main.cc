/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <iostream>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>
#include <l4/re/debug>

#include <l4/sys/thread>
#include <l4/sys/task>

#include <l4/cxx/utils>
#include <l4/cxx/ipc_stream>
#include <l4/cxx/ipc_server>

#include <l4/util/util.h>

#include "debug.h"
#include "device_repo.h"
#include "device_tree.h"
#include "device_factory.h"
#include "guest.h"
#include "monitor_console.h"
#include "ram_ds.h"
#include "virt_bus.h"

__thread unsigned vmm_current_cpu_id;

Vdev::Device_repository devices;

static bool
node_cb(Vdev::Dt_node const &node, unsigned /* depth */, Vmm::Guest *vmm,
        Vmm::Virt_bus *vbus)
{
  cxx::Ref_ptr<Vdev::Device> dev = Vdev::Factory::create_dev(vmm, vbus, node);
  if (dev)
    {
      devices.add(node, dev);
      return true;
    }

  // Device creation failed. Since there is no return code telling us
  // something about the reason we have to guess and to act
  // accordingly. Currently we assume, that the creation of devices
  // with special factory interfaces does not fail. If we have a node
  // with resources, and device creation failed, we do not have enough
  // resources to handle the device.
  if (!node.needs_vbus_resources())
    return true; // no error, just continue parsing the tree

  if (node.has_prop("l4vmm,force-enable"))
    {
      Dbg().printf("Device creation for %s failed, 'l4vmm,force-enable' set\n",
                   node.get_name());
      return true;
    }

  Dbg().printf("Device creation for %s failed. Disabling device \n",
               node.get_name());
  node.setprop_string("status", "disabled");
  return false;
}


static cxx::Ref_ptr<Monitor_console>
create_monitor(Vmm::Guest *vmm)
{
  const char * const capname = "mon";
  auto mon_con_cap = L4Re::Env::env()->get_cap<L4::Vcon>(capname);
  if (!mon_con_cap)
    return nullptr;

  auto moncon = cxx::make_ref_obj<Monitor_console>(capname, mon_con_cap, vmm);
  moncon->register_obj(vmm->registry());

  return moncon;
}


static char const *const options = "+k:d:p:r:c:b:";
static struct option const loptions[] =
  {
    { "kernel",   1, NULL, 'k' },
    { "dtb",      1, NULL, 'd' },
    { "dtb-padding", 1, NULL, 'p' },
    { "ramdisk",  1, NULL, 'r' },
    { "cmdline",  1, NULL, 'c' },
    { "rambase",  1, NULL, 'b' },
    { 0, 0, 0, 0}
  };

static int run(int argc, char *argv[])
{
  L4Re::Env const *e = L4Re::Env::env();
  Dbg info;
  Dbg warn(Dbg::Warn);

  Dbg::set_level(0xffff);

  info.printf("Hello out there.\n");

  char const *cmd_line     = nullptr;
  char const *kernel_image = "rom/zImage";
  char const *device_tree  = nullptr;
  char const *ram_disk     = nullptr;
  l4_addr_t rambase = Vmm::Guest::Default_rambase;
  size_t dtb_padding = 0x200;

  int opt;
  while ((opt = getopt_long(argc, argv, options, loptions, NULL)) != -1)
    {
      switch (opt)
        {
        case 'c': cmd_line     = optarg; break;
        case 'k': kernel_image = optarg; break;
        case 'd': device_tree  = optarg; break;
        case 'r': ram_disk     = optarg; break;
        case 'b':
          rambase = optarg[0] == '-'
                    ? (l4_addr_t)Vmm::Ram_ds::Ram_base_identity_mapped
                    : strtoul(optarg, nullptr, 0);
          break;
        case 'p':
          dtb_padding = strtoul(optarg, nullptr, 0);
          break;
        default:
          Err().printf("unknown command-line option\n");
          return 1;
        }
    }

  // get RAM data space and attach it to our (VMMs) address space
  auto ram = L4Re::chkcap(e->get_cap<L4Re::Dataspace>("ram"),
                          "ram dataspace cap", -L4_ENOENT);
  // create VM BUS connection to IO
  auto vbus_cap = e->get_cap<L4vbus::Vbus>("vbus");
  if (!vbus_cap)
    vbus_cap = e->get_cap<L4vbus::Vbus>("vm_bus");

  auto vbus = cxx::make_ref_obj<Vmm::Virt_bus>(vbus_cap);
  auto vmm = Vmm::Guest::create_instance(ram, rambase);
  auto vcpu = vmm->create_cpu();
  auto mon = create_monitor(vmm);

  vmm->set_fallback_mmio_ds(vbus->io_ds());


  l4_addr_t entry;
  auto load_addr = vmm->load_linux_kernel(kernel_image, &entry);

  if (device_tree)
    {
      load_addr = vmm->load_device_tree_at(device_tree, load_addr, dtb_padding);
      vmm->update_device_tree(cmd_line);

      auto dt = vmm->device_tree();
      auto vbus_val = vbus.get();
      dt.scan([vmm, vbus_val] (Vdev::Dt_node const &node, unsigned depth)
                { return node_cb(node, depth, vmm, vbus_val); },
              [] (Vdev::Dt_node const &, unsigned)
                {});

      devices.init_devices(dt, vmm, vbus.get());
    }

  if (ram_disk)
    {
      l4_size_t rd_size = 0;
      L4virtio::Ptr<void> rd_addr(load_addr);

      vmm->load_ramdisk_at(ram_disk, rd_addr, &rd_size);
      if (device_tree)
        vmm->set_ramdisk_params(rd_addr, rd_size);
    }

  vmm->prepare_linux_run(vcpu, entry, kernel_image, cmd_line);
  vmm->cleanup_ram_state();
  vmm->run(vcpu);

  Err().printf("ERROR: we must never reach this....\n");
  return 0;
}

int main(int argc, char *argv[])
{
  try
    {
      return run(argc, argv);
    }
  catch (L4::Runtime_error &e)
    {
      Err().printf("%s: %s\n", e.str(), e.extra_str());
    }
  return 1;
}
