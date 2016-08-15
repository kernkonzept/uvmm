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

static void scan_device_tree(Vmm::Guest *vmm, Vmm::Virt_bus *vbus)
{
  char path_buf[1024];

  for (auto node = vmm->device_tree().first_node(); node.is_valid();
       node = node.next_node())
    {
      // ignore nodes without compatible property or that are disabled
      if (node.is_compatible("") < 0 || !node.is_enabled())
        continue;

      int pathlen;
      char const *path = node.get_name(&pathlen);
      if (!path)
        continue;

      cxx::Ref_ptr<Vdev::Device> dev = Vdev::Factory::create_dev(vmm, vbus, node);
      if (!dev)
        {
            if (!node.get_prop<char>("l4vmm,force-enable", nullptr)
                && (node.get_prop<char>("reg", nullptr)
                    || node.get_prop<char>("interrupts", nullptr)))
            {
              Err().printf("Device '%.*s' needs resources which cannot be virtualised. Disabled.\n",
                           pathlen, path);
              node.setprop_string("status", "disabled");
            }
        }
      else
        {
          node.get_path(path_buf, sizeof(path_buf));
          devices.add(path_buf, node.get_phandle(), dev);
        }
    }
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

  vmm->set_fallback_mmio_ds(vbus->io_ds());

    {
      const char * const capname = "mon";
      auto mon_con_cap = L4Re::Env::env()->get_cap<L4::Vcon>(capname);
      if (mon_con_cap)
        {
          Monitor_console *moncon = new Monitor_console(capname,
                                                        mon_con_cap, vmm);
          moncon->register_obj(vmm->registry());
        }
    }

  l4_addr_t entry;
  auto load_addr = vmm->load_linux_kernel(kernel_image, &entry);

  if (device_tree)
    {
      load_addr = vmm->load_device_tree_at(device_tree, load_addr, dtb_padding);
      vmm->update_device_tree(cmd_line);

      auto dt = vmm->device_tree();
      scan_device_tree(vmm, vbus.get());
      devices.init_devices(dt);
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
