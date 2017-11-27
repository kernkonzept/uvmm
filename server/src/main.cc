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
#include <l4/sys/cache.h>

#include "debug.h"
#include "device_tree.h"
#include "device_factory.h"
#include "guest.h"
#include "monitor_console.h"
#include "ram_ds.h"
#include "vm.h"

Vmm::Vm vm_instance;

static Dbg info(Dbg::Core, Dbg::Info, "main");
static Dbg warn(Dbg::Core, Dbg::Warn, "main");

static bool
node_cb(Vdev::Dt_node const &node)
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
    dev = vm_instance.cpus()->create_vcpu(&node);
  else
    dev = Vdev::Factory::create_dev(&vm_instance, node);

  if (dev)
    {
      vm_instance.add_device(node, dev);
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
create_monitor()
{
  const char * const capname = "mon";
  auto mon_con_cap = L4Re::Env::env()->get_cap<L4::Vcon>(capname);
  if (!mon_con_cap)
    return nullptr;

  auto moncon = cxx::make_ref_obj<Monitor_console>(capname, mon_con_cap,
                                                   &vm_instance);
  moncon->register_obj(vm_instance.vmm()->registry());

  return moncon;
}

static Vdev::Device_tree
load_device_tree_at(Vmm::Ram_ds *ram, char const *name, L4virtio::Ptr<void> addr,
                    l4_size_t padding)
{
  ram->load_file(name, addr);

  auto dt = Vdev::Device_tree(ram->access(addr));
  dt.check_tree();
  // use 1.25 * size + padding for the time being
  dt.add_to_size(dt.size() / 4 + padding);
  info.printf("Loaded device tree to %llx:%llx\n", addr.get(),
                addr.get() + dt.size());

  return dt;
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
    { "guest", "core", "cpu", "mmio", "irq", "dev", "pm", "vbus_event" };

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

static int run(int argc, char *argv[])
{
  unsigned long verbosity = Dbg::Warn;

  Dbg::set_verbosity(verbosity);

  int use_wakeup_inhibitor = 0;
  int use_mmio_fallback = 0;
  char const *const options = "+k:d:p:r:c:b:vqD:";
  struct option const loptions[] =
    {
      { "kernel",   1, NULL, 'k' },
      { "dtb",      1, NULL, 'd' },
      { "dtb-padding", 1, NULL, 'p' },
      { "ramdisk",  1, NULL, 'r' },
      { "cmdline",  1, NULL, 'c' },
      { "rambase",  1, NULL, 'b' },
      { "mmio-fallback", 0, &use_mmio_fallback, 1 },
      { "debug",    1, NULL, 'D' },
      { "verbose",  0, NULL, 'v' },
      { "quiet",    0, NULL, 'q' },
      { "wakeup-on-system-resume", 0, &use_wakeup_inhibitor, 1},
      { 0, 0, 0, 0}
    };

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
        case 0:
          break;
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

  vm_instance.create_default_devices(rambase);
  auto mon = create_monitor();

  auto *vmm = vm_instance.vmm();
  auto *ram = vm_instance.ram().get();

  vmm->use_wakeup_inhibitor(use_wakeup_inhibitor);
  if (use_mmio_fallback)
    vmm->set_fallback_mmio_ds(vm_instance.vbus()->io_ds());

  Vdev::Device_tree dt(nullptr);
  L4virtio::Ptr<void> dt_addr(0);
  l4_addr_t entry;
  info.printf("Loading kernel...\n");
  auto next_free_addr = vmm->load_linux_kernel(ram, kernel_image, &entry);

  if (device_tree)
    {
      info.printf("Loading device tree...\n");
      dt_addr = next_free_addr;
      dt = load_device_tree_at(ram, device_tree, dt_addr, dtb_padding);
      // assume /choosen and /memory is present at this point

      if (cmd_line)
        {
          auto node = dt.path_offset("/chosen");
          node.setprop_string("bootargs", cmd_line);
        }

      ram->setup_device_tree(dt);
      vmm->setup_device_tree(dt);

      dt.scan([] (Vdev::Dt_node const &node, unsigned /* depth */)
                { return node_cb(node); },
              [] (Vdev::Dt_node const &, unsigned)
                {});

      vm_instance.init_devices(dt);

      // Round to the next page to load anything else to a new page.
      next_free_addr =
        l4_round_size(L4virtio::Ptr<void>(dt_addr.get() + dt.size()),
                                          L4_PAGESHIFT);
    }

  if (!vm_instance.cpus()->vcpu_exists(0))
    {
      // Verify cpu setup - if there is no CPU0 there should be no other CPU
      auto cpus = vm_instance.cpus().get();
      for (auto cpu: *cpus)
        if (cpu)
          L4Re::chksys(-L4_EINVAL, "Invalid CPU configuration in device tree,"
                       " missing CPU0");

      vm_instance.cpus()->create_vcpu(nullptr);
    }

  if (ram_disk)
    {
      info.printf("Loading ram disk...\n");
      l4_size_t rd_size = 0;
      auto rd_start = next_free_addr;
      next_free_addr = ram->load_file(ram_disk, rd_start, &rd_size);

      if (device_tree && rd_size > 0)
        {
          auto node = dt.path_offset("/chosen");
          node.set_prop_address("linux,initrd-start", rd_start.get());
          node.set_prop_address("linux,initrd-end",
                                rd_start.get() + rd_size);
        }

      next_free_addr = l4_round_size(next_free_addr, L4_PAGESHIFT);

      info.printf("Loaded ramdisk image %s to [%llx:%llx] (%08zx)\n",
                  ram_disk, rd_start.get(), next_free_addr.get() - 1,
                  rd_size);
    }

  l4_addr_t dt_boot_addr = device_tree ? ram->boot_addr(dt_addr) : 0;
  vmm->prepare_linux_run(vm_instance.cpus()->vcpu(0), entry, ram, kernel_image,
                         cmd_line, dt_boot_addr);

  // XXX Some of the RAM memory might have been unmapped during copy_in()
  // of the binary and the RAM disk. The VM paging code, however, expects
  // the entire RAM to be present. Touch the RAM region again, now that
  // setup has finished to remap the missing parts.
  ram->touch_rw();

  if (device_tree)
    {
      l4_addr_t ds_start =
          reinterpret_cast<l4_addr_t>(ram->access(dt_addr));
      l4_addr_t ds_end = ds_start + dt.size();
      l4_cache_clean_data(ds_start, ds_end);
      info.printf("Cleaning caches [%lx-%lx] ([%llx])\n",
                  ds_start, ds_end, dt_addr.get());
    }

  vmm->run(vm_instance.cpus());

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
      if (e.extra_str() && e.extra_str()[0] != '\0')
        Err().printf("%s: %s\n", e.str(), e.extra_str());
      else
        Err().printf("%s\n", e.str());
    }
  return 1;
}
