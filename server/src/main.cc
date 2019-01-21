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
#include <cstring>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <l4/re/env>

#include "debug.h"
#include "guest.h"
#include "host_dt.h"
#include "monitor_console.h"
#include "vm_ram.h"
#include "vm.h"

static Vmm::Vm vm_instance;

static Dbg info(Dbg::Core, Dbg::Info, "main");
static Dbg warn(Dbg::Core, Dbg::Warn, "main");

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

  vm_instance.create_default_devices();
  auto mon = Monitor_console::create(&vm_instance);
  Vdev::Host_dt dt;

  auto *vmm = vm_instance.vmm();
  auto *ram = vm_instance.ram().get();

  char const *const options = "+k:d:r:c:b:vqD:";
  struct option const loptions[] =
    {
      { "kernel",                  required_argument, NULL, 'k' },
      { "dtb",                     required_argument, NULL, 'd' },
      { "ramdisk",                 required_argument, NULL, 'r' },
      { "cmdline",                 required_argument, NULL, 'c' },
      { "rambase",                 required_argument, NULL, 'b' },
      { "debug",                   required_argument, NULL, 'D' },
      { "verbose",                 no_argument,       NULL, 'v' },
      { "quiet",                   no_argument,       NULL, 'q' },
      { "wakeup-on-system-resume", no_argument,       NULL, 'W' },
      { 0, 0, 0, 0}
    };

  char const *cmd_line     = nullptr;
  char const *kernel_image = "rom/zImage";
  char const *ram_disk     = nullptr;
  l4_addr_t rambase = Vmm::Guest::Default_rambase;

  int opt;
  while ((opt = getopt_long(argc, argv, options, loptions, NULL)) != -1)
    {
      switch (opt)
        {
        case 0:
          break;
        case 'c': cmd_line     = optarg; break;
        case 'k': kernel_image = optarg; break;
        case 'd':
          dt.add_source(optarg);
          break;
        case 'r': ram_disk     = optarg; break;
        case 'b':
          rambase = optarg[0] == '-'
                    ? (l4_addr_t)Vmm::Ram_ds::Ram_base_identity_mapped
                    : strtoul(optarg, nullptr, 0);
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
        case 'W':
          vmm->use_wakeup_inhibitor(true);
          break;
        default:
          Err().printf("unknown command-line option\n");
          return 1;
        }
    }

  warn.printf("Hello out there.\n");

  Vmm::Ram_free_list ram_free_list
    = ram->setup_from_device_tree(dt, vmm->memmap(), Vmm::Guest_addr(rambase));

  info.printf("Loading kernel...\n");
  l4_addr_t entry = vmm->load_linux_kernel(ram, kernel_image, &ram_free_list);

  if (dt.valid())
    {
      // assume /choosen and /memory is present at this point

      if (cmd_line)
        {
          auto node = dt.get().path_offset("/chosen");
          node.setprop_string("bootargs", cmd_line);
        }

      vm_instance.scan_device_tree(dt.get());
    }

  if (!vm_instance.cpus()->vcpu_exists(0))
    {
      // Verify cpu setup - if there is no CPU0 there should be no other CPU
      auto cpus = vm_instance.cpus().get();
      for (auto cpu: *cpus)
        if (cpu)
          L4Re::chksys(-L4_EINVAL, "Invalid CPU configuration in device tree,"
                       " missing CPU0");

      // XXX The CPU device is not added to the device repository here. Is this
      // necessary? The cpu_dev_array still holds a reference to it so it
      // doesn't simply vanish here ...
      vm_instance.cpus()->create_vcpu(nullptr);
    }

  if (ram_disk)
    {
      info.printf("Loading ram disk...\n");
      Vmm::Guest_addr rd_start;
      l4_size_t rd_size;
      L4Re::chksys(ram_free_list.load_file_to_back(ram, ram_disk, &rd_start,
                                                   &rd_size),
                   "Copy ram disk into RAM.");

      if (dt.valid() && rd_size > 0)
        {
          auto node = dt.get().path_offset("/chosen");
          node.set_prop_address("linux,initrd-start", rd_start.get());
          node.set_prop_address("linux,initrd-end",
                                rd_start.get() + rd_size);
        }

      info.printf("Loaded ramdisk image %s to %lx (size: %08zx)\n",
                  ram_disk, rd_start.get(), rd_size);
    }

  // finally copy in the device tree
  l4_addr_t dt_boot_addr = 0;
  if (dt.valid())
    dt_boot_addr = ram->move_in_device_tree(&ram_free_list, cxx::move(dt));

  vmm->prepare_linux_run(vm_instance.cpus()->vcpu(0), entry, ram, kernel_image,
                         cmd_line, dt_boot_addr);

  info.printf("Populating RAM of virtual machine\n");
  vmm->map_eager();

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
        Err().printf("%s: %s\n", e.extra_str(), e.str());
      else
        Err().printf("%s\n", e.str());
    }
  return 1;
}
