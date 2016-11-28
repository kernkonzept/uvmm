-- vi:ft=lua

package.path = "rom/?.lua";

local L4 = require "L4";
local vmm = require "vmm";

vmm.loader.log_fab = L4.default_loader:new_channel();

-- start cons server for console multiplexing
L4.default_loader:start(
  {
    scheduler = vmm.new_sched(0x40);
    log = L4.Env.log,
    caps = { cons = vmm.loader.log_fab:svr() }
  }, "rom/cons -a");


-- virtual IO busses
local io_busses = {
  vm_hw = 1,
  vm_nohw = 1,
}

-- virtio network ports
local net_ports = {
  net0 = 1,
  net1 = 1,
}

local common_bootargs = "console=hvc0 earlyprintk=1";

vmm.start_io(io_busses, "rom/io.cfg");
vmm.start_virtio_switch(net_ports, 0xa, 0x1);
vmm.start_vm{
  id=1,
  mem=128,
  vbus=io_busses.vm_hw,
  net=net_ports.net0,
  rd="rom/ramdisk-arm.rd",
  fdt="rom/virt-omap5.dtb",
  --bootargs=common_bootargs .. " ip=192.168.1.1:::255.255.255.0:server:eth0 root=/dev/sda1",
  bootargs=common_bootargs .. " ramdisk_size=9100 root=/dev/ram",
  prio=nil, cpus=0x1
};

vmm.start_vm{
  id=2,
  mem=128,
  vbus=io_busses.vm_nohw,
  net=net_ports.net1,
  rd="rom/ramdisk-arm.rd",
  fdt="rom/virt-omap5.dtb",
  bootargs=common_bootargs .. " ramdisk_size=9100 root=/dev/ram",
  prio=nil, cpus=0x1
};
