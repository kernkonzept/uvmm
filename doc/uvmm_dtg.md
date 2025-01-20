# uvmm_dtg The device tree generator for Uvmm {#l4re_servers_uvmm_uvmm_dtg}

A virtual machine in Uvmm is configured with a device tree that contains
information about the VMs resources, memory layout, virtual CPUs and
peripheral devices.

Uvmm_dtg is a tool to generate such a device tree at runtime according to its
command line.

## Usage  in L4Re

Example lua script for Ned:

    -- Create DS holding device tree
    local dt = L4.Env.user_factory:create(L4.Proto.Dataspace, 4 * 1024):m("rw");
   
    -- Start the generator
    L4.default_loader:start(
    {
      caps = { dt = dt },
    }, "rom/uvmm_dtg dt"):wait();
   
    -- Start uvmm
    vmm.start_vm
    {
     ...
     ext_caps = { dt = dt },
     fdt = "dt",
     ...
    }

Please notice the `:wait()` when starting `uvmm_dtg`. This makes Ned pause
until uvmm_dtg has exited and put the device tree into the dataspace such that
Uvmm can commence.

## Usage

`uvmm_dtg [OPTION]... <file>|--`

* `--`
  print to stdout

* `file`

  On L4Re, the string given as `<file>` is interpreted as a named capability
  which needs to be backed by a sufficiently large Dataspace. On
  Linux, a file with the given name is created. In both cases,
  uvmm_dtg will output into the named file.

### Options

* `-h`

  Show help.

* `--arch <target architecture>`

  Select the target architecture. Valid options are `x86`, `x86_64`, `arm32`,
  `arm64`, `mips32` and `mips64`.

* `--format <format>`

  Select the output format. Available formats are:
  `txt`: The device tree will be printed as plain text (`dts`).
  `bin`: The device tree will be output as binary (`dtb`).

* `--mem-base <membase>`

  Configure the start of the memory distribution. `membase` can be defined in
  both decimal and hex notations. uvmm_dtg rounds the given base up to the
  platforms page size.

  This value can be overridden by memory devices with fixed addresses.

* `--device <devicename:[Option1,Option2=value,Option3=value,...]>`

  This configures a device.

  To get a list of supported devices, use `-device help`.

  To get help for a specific device, use `-device devicename:help`.
