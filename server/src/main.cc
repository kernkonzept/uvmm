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
#include "vcpu_array.h"

Vdev::Device_repository devices;

static Dbg info(Dbg::Core, Dbg::Info, "main");
static Dbg warn(Dbg::Core, Dbg::Warn, "main");

static bool
node_cb(Vdev::Dt_node const &node, unsigned /* depth */, Vmm::Guest *vmm,
        cxx::Ref_ptr<Vmm::Vcpu_array> cpus, Vmm::Virt_bus *vbus)
{
  cxx::Ref_ptr<Vdev::Device> dev;
  char const *devtype = node.get_prop<char>("device_type", nullptr);
  bool is_cpu_dev = devtype && strcmp("cpu", devtype) == 0;
  if (is_cpu_dev)
    {
      // Cpu devices need to be treated specially because they
      // use a different factory.
      auto *cpuid = node.get_prop<fdt32_t>("reg", nullptr);
      if (!cpuid)
        {
          Err().printf("Cpu has missing reg property. Ignored.\n");
          return true;
        }

      // If a compatible property exists, it may be used to specify
      // the reported CPU type (if supported by architecture). Without
      // compatible property, the default is used.
      auto const *compatible = node.get_prop<char>("compatible", nullptr);

      dev = cpus->create_vcpu(fdt32_to_cpu(cpuid[0]), compatible);
    }
  else
    dev = Vdev::Factory::create_dev(vmm, vbus, node);

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
  if (!is_cpu_dev && !node.needs_vbus_resources())
    return true; // no error, just continue parsing the tree

  if (node.has_prop("l4vmm,force-enable"))
    {
      warn.printf("Device creation for %s failed, 'l4vmm,force-enable' set\n",
                  node.get_name());
      return true;
    }

  warn.printf("Device creation for %s failed. Disabling device \n",
              node.get_name());

  node.setprop_string("status", "disabled");
  return false;
}


static cxx::Ref_ptr<Monitor_console>
create_monitor(Vmm::Guest *vmm, cxx::Ref_ptr<Vmm::Vcpu_array> const &cpus)
{
  const char * const capname = "mon";
  auto mon_con_cap = L4Re::Env::env()->get_cap<L4::Vcon>(capname);
  if (!mon_con_cap)
    return nullptr;

  auto moncon = cxx::make_ref_obj<Monitor_console>(capname, mon_con_cap,
                                                   vmm, cpus);
  moncon->register_obj(vmm->registry());

  return moncon;
}


static int
verbosity_mask_from_string(char const *str, unsigned *mask)
{
  if (strcmp("quiet", str) == 0)
    {
      *mask = Dbg::Quiet;
      return 0;
    }
  if (strcmp("warn", str) == 0)
    {
      *mask = Dbg::Warn;
      return 0;
    }
  if (strcmp("info", str) == 0)
    {
      *mask = Dbg::Warn | Dbg::Info;
      return 0;
    }
  if (strcmp("trace", str) == 0)
    {
      *mask = Dbg::Warn | Dbg::Info | Dbg::Trace;
      return 0;
    }

  return -L4_ENOENT;
}

/**
 * Set debug level according to a verbosity string.
 *
 * The string may either set a global verbosity level:
 *   quiet, warn, info, trace
 *
 * Or it may set the verbosity level for a component:
 *
 *   <component>=<level>
 *
 * where component is one of: guest, core, cpu, mmio, irq, dev
 * and level the same as above.
 *
 * To change the verbosity of multiple components repeat
 * the verbosity switch.
 *
 * Example:
 *
 *  uvmm -D info -D irq=trace
 *
 *    Sets verbosity for all components to info except for
 *    IRQ handling which is set to trace.
 *
 *  uvmm -D trace -D dev=warn -D mmio=warn
 *
 *    Enables tracing for all components except devices
 *    and mmio.
 *
 */
static void
set_verbosity(char const *str)
{
  unsigned mask;
  if (verbosity_mask_from_string(str, &mask) == 0)
    {
      Dbg::set_verbosity(mask);
      return;
    }

  static char const *const components[] =
    { "guest", "core", "cpu", "mmio", "irq", "dev" };

  static_assert(std::extent<decltype(components)>::value == Dbg::Max_component,
                "Component names must match 'enum Component'.");

  for (unsigned i = 0; i < Dbg::Max_component; ++i)
    {
      auto len = strlen(components[i]);
      if (strncmp(components[i], str, len) == 0 && str[len] == '='
          && verbosity_mask_from_string(str + len + 1, &mask) == 0)
        {
          Dbg::set_verbosity(i, mask);
          return;
        }
    }
}

static char const *const options = "+k:d:p:r:c:b:vqD:";
static struct option const loptions[] =
  {
    { "kernel",   1, NULL, 'k' },
    { "dtb",      1, NULL, 'd' },
    { "dtb-padding", 1, NULL, 'p' },
    { "ramdisk",  1, NULL, 'r' },
    { "cmdline",  1, NULL, 'c' },
    { "rambase",  1, NULL, 'b' },
    { "debug",    1, NULL, 'D' },
    { "verbose",  0, NULL, 'v' },
    { "quiet",    0, NULL, 'q' },
    { 0, 0, 0, 0}
  };

static int run(int argc, char *argv[])
{
  L4Re::Env const *e = L4Re::Env::env();
  unsigned long verbosity = Dbg::Warn;

  Dbg::set_verbosity(verbosity);

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
        case 'q':
          // quiet actually means guest output only
          verbosity = Dbg::Quiet;
          Dbg::set_verbosity(verbosity);
          Dbg::set_verbosity(Dbg::Guest, Dbg::Warn);
          break;
        case 'v':
          verbosity = (verbosity << 1) | 1;
          Dbg::set_verbosity(verbosity);
          break;
        case 'D':
          set_verbosity(optarg);
          break;
        default:
          Err().printf("unknown command-line option\n");
          return 1;
        }
    }

  warn.printf("Hello out there.\n");

  // get RAM data space and attach it to our (VMMs) address space
  auto ram = L4Re::chkcap(e->get_cap<L4Re::Dataspace>("ram"),
                          "ram dataspace cap", -L4_ENOENT);
  // create VM BUS connection to IO
  auto vbus_cap = e->get_cap<L4vbus::Vbus>("vbus");
  if (!vbus_cap)
    vbus_cap = e->get_cap<L4vbus::Vbus>("vm_bus");

  auto vbus = cxx::make_ref_obj<Vmm::Virt_bus>(vbus_cap);
  auto vmm = Vmm::Guest::create_instance(ram, rambase);
  auto vcpus = Vdev::make_device<Vmm::Vcpu_array>();
  auto mon = create_monitor(vmm, vcpus);

  vmm->set_fallback_mmio_ds(vbus->io_ds());


  l4_addr_t entry;
  auto load_addr = vmm->load_linux_kernel(kernel_image, &entry);

  if (device_tree)
    {
      load_addr = vmm->load_device_tree_at(device_tree, load_addr, dtb_padding);
      vmm->update_device_tree(cmd_line);

      auto dt = vmm->device_tree();
      auto vbus_val = vbus.get();
      dt.scan([vmm, vcpus, vbus_val] (Vdev::Dt_node const &node, unsigned depth)
                { return node_cb(node, depth, vmm, vcpus, vbus_val); },
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

  vmm->prepare_linux_run(vcpus->vcpu(0), entry, kernel_image, cmd_line);
  vmm->cleanup_ram_state();
  vmm->run(vcpus);

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
