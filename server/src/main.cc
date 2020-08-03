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
#include <terminate_handler-l4>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <l4/re/env>
#include <l4/re/random>

#include "debug.h"
#include "guest.h"
#include "host_dt.h"
#include "vm_ram.h"
#include "vm.h"
#include "monitor/monitor.h"

static Vmm::Vm vm_instance;

static Dbg info(Dbg::Core, Dbg::Info, "main");
static Dbg warn(Dbg::Core, Dbg::Warn, "main");

/**
 * Verify the CPU setup from the device tree.
 *
 * The device tree may not have set up any CPU explicitly. Then create a
 * single CPU setup. If CPUs have been setup, then CPU0 must be among them.
 */
static void
verify_cpu0_setup()
{
  if (vm_instance.cpus()->vcpu_exists(0))
    return;

  // If there is no CPU0 there should be no other CPU.
  for (auto cpu: *vm_instance.cpus().get())
    if (cpu)
      L4Re::chksys(-L4_EINVAL, "Invalid CPU configuration in device tree,"
                               " missing CPU0");

  // XXX The CPU device is not added to the device repository here. Is this
  // necessary? The cpu_dev_array still holds a reference to it so it
  // doesn't simply vanish here ...
  vm_instance.cpus()->create_vcpu(nullptr);
}

/**
 * Set up the ram disk in memory and configure it in the device tree.
 *
 * \param ram_disk       Name of the dataspace containing the ram disk.
 *                       May be nullptr if no ram disk is configured.
 * \param dt             Device tree to add ram disk information to.
 * \param ram_free_list  Free list for memory in `ram`.
 * \param ram            Physical guest ram.
 */
static void
setup_ramdisk(char const *ram_disk, Vdev::Host_dt const &dt,
              Vmm::Ram_free_list *ram_free_list, Vmm::Vm_ram *ram)
{
  if (!ram_disk)
    return;

  info.printf("Loading ram disk...\n");
  Vmm::Guest_addr rd_start;
  l4_size_t rd_size;
  L4Re::chksys(ram_free_list->load_file_to_back(ram, ram_disk, &rd_start,
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

static void
setup_kaslr_seed(Vdev::Host_dt const &dt)
{
  auto c = L4Re::Env::env()->get_cap<L4Re::Random>("rng");
  if (!c)
    return;

  union
  {
    l4_uint64_t r;
    char c[sizeof(l4_uint64_t)];
  } random;

  L4::Ipc::Array<char, unsigned long> msg(sizeof(random), random.c);
  int ret = c->get_random(sizeof(random), &msg);
  if (ret < (int) sizeof(random))
    L4Re::throw_error(ret < 0 ? ret : -L4_EAGAIN,
                      "Getting random seed for KASLR initialisation.");


  auto node = dt.get().path_offset("/chosen");
  node.setprop_u64("kaslr-seed", random.r);
}

static char const *const options = "+k:d:r:c:b:vqD:";
static struct option const loptions[] =
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

int main(int argc, char *argv[])
{
  unsigned long verbosity = Dbg::Warn;

  Dbg::set_verbosity(verbosity);

  Vdev::Host_dt dt;

  char const *cmd_line     = nullptr;
  char const *kernel_image = "rom/zImage";
  char const *ram_disk     = nullptr;
  l4_addr_t rambase = Vmm::Guest::Default_rambase;
  bool use_wakeup_inhibitor = false;

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
          break;
        case 'v':
          verbosity = (verbosity << 1) | 1;
          Dbg::set_verbosity(verbosity);
          break;
        case 'D':
          if (Dbg::set_verbosity(optarg) != L4_EOK)
            warn.printf("Failed to set verbosity\n");
          break;
        case 'W':
          use_wakeup_inhibitor = true;
          break;
        default:
          Err().printf("unknown command-line option\n");
          return 1;
        }
    }

  Vmm::Cpu_dev::alloc_main_vcpu();
  vm_instance.create_default_devices();

  auto *vmm = vm_instance.vmm();
  auto *ram = vm_instance.ram().get();

  if (use_wakeup_inhibitor)
    vm_instance.pm()->use_wakeup_inhibitor(true);

  warn.printf("Hello out there.\n");

  Monitor::enable_cmd_control(&vm_instance);

  Vmm::Ram_free_list ram_free_list
    = ram->setup_from_device_tree(dt, vmm->memmap(), Vmm::Guest_addr(rambase));

  info.printf("Loading kernel...\n");
  l4_addr_t entry = vmm->load_linux_kernel(ram, kernel_image, &ram_free_list);

  dt.set_command_line(cmd_line);

  setup_ramdisk(ram_disk, dt, &ram_free_list, ram);

  if (dt.valid())
    {
      vm_instance.scan_device_tree(dt.get());
      setup_kaslr_seed(dt);
    }

  verify_cpu0_setup();

  // finally copy in the device tree
  l4_addr_t dt_boot_addr = 0;
  if (dt.valid())
    dt_boot_addr = ram->move_in_device_tree(&ram_free_list, cxx::move(dt));

  vmm->prepare_generic_platform(&vm_instance);
  vmm->prepare_platform(&vm_instance);
  vmm->prepare_linux_run(vm_instance.cpus()->vcpu(0), entry, ram, kernel_image,
                         cmd_line, dt_boot_addr);

  info.printf("Populating RAM of virtual machine\n");
  vmm->map_eager();

  vmm->run(vm_instance.cpus());

  Err().printf("ERROR: we must never reach this....\n");
  return 0;
}
