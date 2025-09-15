--! \file vmm.lua

local L4 = require "L4";

local l = L4.Loader.new({mem = L4.Env.user_factory});
loader = l;

--[[!
  \internal

  Utility function to merge several lua tables

  \param ... one or more tables

  \note Later tables are given more priority when merging

  \return a new combined table
]]
function table_override(...)
  local combined = {}
  for _, tab in ipairs({...}) do
    for k, v in pairs(tab) do
      combined[k] = v
    end
  end
  return combined
end

--[[!
  Creates a new scheduler proxy at moe.

  \param prio     Base priority of the threads running in the scheduler proxy
  \param cpu_mask First of a list of CPU masks for the first 64 CPUs to use for
                  the scheduler proxy
  \param ...      more CPU masks

  \return created scheduler
]]
function new_sched(prio, cpu_mask, ...)
  return  L4.Env.user_factory:create(L4.Proto.Scheduler, prio + 10, prio,
                                     cpu_mask, ...);
end

--[[!
  Start IO service with the given options

  \param[in,out] busses  table of vBus names as keys. Uses io config
                         `<name>.vbus` to fill vBus `<name>`.
  \param         cmdline io command line parameters
  \param         opts    Option table for loader.start function, e.g. scheduler
                         or ext_caps. Entries from ext_caps have precedence over
                         default caps created by this function.

  After this function returns the created vBusses are located in the table
  passed as `busses`.
]]
function start_io(busses, cmdline, opts)
  if opts == nil then opts = {} end

  if opts.caps ~= nil then
    print("Warning: use opts.ext_caps to pass custom/additional capabilities.")
  end

  if opts.scheduler == nil then
    print("IO started with base priority. Risk of priority related deadlocks! "
          .. "Provide an opts.scheduler entry.")
  end

  local caps = {
    sigma0 = L4.cast(L4.Proto.Factory, L4.Env.sigma0):create(L4.Proto.Sigma0);
    icu    = L4.Env.icu;
    iommu  = L4.Env.iommu;
  };

  local files = "";

  for k, v in pairs(busses) do
    if caps[k] ~= nil then
      print("Warning: overwriting caps." .. k .. " with vbus of same name.")
    end
    local c = l:new_channel();
    busses[k] = c
    caps[k] = c:svr();
    files = files .. " rom/" .. k .. ".vbus";
  end

  opts.caps = table_override(caps, opts.caps or {}, opts.ext_caps or {})
  opts.log  = opts.log or { "io", "red" }

  return l:start(opts, "rom/io " .. cmdline .. files)
end

--[[!
  Create scheduler proxy and add it into the `opts` table under
  the key `scheduler`.

  \param[in,out]  opts  option table
  \param          prio  thread priority (or `nil`)
  \param          cpus  cpu mask (or `nil`)
  \param          ...   more CPU masks

  There are four possibilities for values of prio and cpus:

  \li No prio and no cpus: No scheduler proxy created.
  \li A prio, but no cpus: Create a scheduler proxy with only a priority limit.
  \li No Prio, but cpus: Create a scheduler proxy with default prio and cpus
      limit.
  \li A prio and cpus: Create a scheduler proxy with given limits.
]]
function set_sched(opts, prio, cpus, ...)
  if cpus == nil and prio == nil then
    return
  end

  if prio == nil then
    -- Default to zero to use the L4Re Default_thread_prio
    prio = 0
  end

  local sched = new_sched(prio, cpus, ...);
  opts["scheduler"] = sched;
end

--[[!
  Start virtio network application.

  \deprecated This function exists for backwards compatiblity reasons and calls
              \ref start_virtio_switch_tbl with an appropriate `options` table

  \param[in,out] ports       table with port names as keys
  \param         prio        priority for started thread
  \param         cpus        cpu mask for started thread
  \param         switch_type Selects application to start. Either `switch` or `p2p`
  \param         ext_caps    Extra capabilities to pass to the started application

  The switch_type `switch` can take additional arguments to create a port at the
  switch. To pass these arguments for a specific port, pass a table as value for
  a key in the ports table.

]]
function start_virtio_switch(ports, prio, cpus, switch_type, ext_caps)
  local opts = {
    ports = ports,
    switch_type = switch_type,
    ext_caps = ext_caps,
  }
  set_sched(opts, prio, cpus)
  return start_virtio_switch_tbl(opts)
end

--[[!
  Start virtio network application.

  \param options  A table of parameters

  The following keys are supported in the `options` table:

  | table key    | value                                                            |
  | ------------ | ---------------------------------------------------------------- |
  | `ports`      | table with port names as keys                                    |
  | `scheduler`  | scheduler (e.g. created with new_sched)                          |
  | `switch_type`| selects application to start. Either `switch` or `p2p`           |
  | `ext_caps`   | Extra capabilities to pass to the started application            |
  | `svr_cap`    | cap slot to be used for the server interface                     |
  | `port_limit` | the maximum number of dynamic ports the switch shall support     |

  The switch_type `switch` can take additional arguments to create a port at the
  switch. To pass these arguments for a specific port, pass a table as value for
  a key in the ports table.

  \note The `svr_cap` capability requires server rights, use ":svr()".
]]
function start_virtio_switch_tbl(options)
  local ports = options.ports;
  local scheduler = options.scheduler;
  local switch_type = options.switch_type;
  local ext_caps = options.ext_caps;
  local svr_cap = options.svr_cap;
  local port_limit = options.port_limit;

  if svr_cap and port_limit == nil then
    print("Warning: start_virtio_switch_tbl(): 'svr_cap' defined, but no "..
          "'port_limit' set. The svr_cap will not support dynamic port "..
          "creation.")
  end

  if port_limit and svr_cap == nil then
    error("start_virtio_switch_tbl(): 'port_limit' set, but no 'svr_cap'. "..
          "This is not supported")
  end

  local switch

  if svr_cap then
    switch = svr_cap:svr()
  else
    switch = l:new_channel()
  end

  local opts = {
    log = { "switch", "Blue" },
    caps = table_override({ svr = switch:svr() }, ext_caps or {});
  };

  if scheduler then
    opts["scheduler"] = scheduler;
  end

  if switch_type == "switch" then
    local port_count = 0;
    for k, v in pairs(ports) do
      port_count = port_count + 1;
    end
    if port_limit then
      port_count = port_count + port_limit
    end

    svr = l:start(opts, "rom/l4vio_switch -v -p " .. port_count );

    for k, extra_opts in pairs(ports) do
      if type(extra_opts) ~= "table" then
        extra_opts = {}
      end

      ports[k] = L4.cast(L4.Proto.Factory, switch):create(
          0,
          "ds-max=4",
          "name=" .. k,
          table.unpack(extra_opts)
      )
    end
  else
    svr = l:start(opts, "rom/l4vio_net_p2p");

    for k, v in pairs(ports) do
      ports[k] = L4.cast(L4.Proto.Factory, switch):create(0, "ds-max=4");
    end
  end

  return svr;
end

--[[!
  Start UVMM

  \param options  A table of parameters

  The following keys are supported in the `options` table:

  | table key   | value                                                            |
  | ----------- | ---------------------------------------------------------------- |
  | `bootargs`  | command line for guest kernel                                    |
  | `cpus`      | cpu mask                                                         |
  | `ext_args`  | additional arguments to pass to UVMM                             |
  | `fdt`       | file name of the device tree                                     |
  | `id`        | an integer identifying the VM                                    |
  | `jdb`       | jdb capability                                                   |
  | `kernel`    | file name of the guest kernel binary                             |
  | `mem`       | RAM size in MiB \e or dataspace cap for guest memory.            |
  | `mem_align` | alignment for the guest memory in bits. Ignored if mem is a cap. |
  | `mon`       | monitor application file name                                    |
  | `net`       | a virtio cap, e.g. for network                                   |
  | `prio`      | thread priority                                                  |
  | `ram_base`  | start of guest memory                                            |
  | `rd`        | file name of the ramdisk                                         |
  | `scheduler` | a scheduler cap. If used, prio and cpus are ignored.             |
  | `vbus`      | the vBus to attach to the VM                                     |
]]
function start_vm(options)
  local nr      = options.id;
  local size_mb = 0;
  local vbus    = options.vbus;
  local vnet    = options.net;
  local prio    = options.prio;
  local cpus    = options.cpus;
  local scheduler = options.scheduler;

  local align   = 10;
  if L4.Info.arch() == "arm" then
    align = 28;
  elseif L4.Info.arch() == "arm64" then
    align = 21;
  end
  align = options.mem_align or align;

  local cmdline = {};
  if options.fdt then
    if type(options.fdt) ~= "table" then
      options.fdt = { options.fdt }
    end
    for _,v in ipairs(options.fdt) do
      cmdline[#cmdline+1] = "-d" .. v;
    end
  end

  if options.bootargs then
    cmdline[#cmdline+1] = "-c" .. options.bootargs;
  end

  if options.rd then
    cmdline[#cmdline+1] = "-r" .. options.rd;
  end

  if options.kernel then
    cmdline[#cmdline+1] = "-k" .. options.kernel;
  end

  if options.ram_base then
    cmdline[#cmdline+1] = "-b" .. options.ram_base;
  end

  local keyb_shortcut = nil;
  if nr ~= nil then
    keyb_shortcut = "key=" .. nr;
  end

  local vm_ram;
  if type(options.mem) == "userdata" then
    -- User gave us a cap. Using this as dataspace for guest RAM.
    vm_ram = options.mem
  elseif type(options.mem) == "number" then
    -- User gave us a number. Using this as size for a new Dataspace.
    size_mb = options.mem
  elseif type(options.mem) == "string" then
    print("start_vm: mem parameter '" .. options.mem .. "' is of type string, "
          .. "please use integer.");
    size_mb = tonumber(options.mem)
  else
    -- User did not give us any valid value.
    size_mb = 16
  end

  if size_mb > 0 then
    local mem_flags = L4.Mem_alloc_flags.Continuous
                    | L4.Mem_alloc_flags.Pinned
                    | L4.Mem_alloc_flags.Super_pages;

    vm_ram = L4.Env.user_factory:create(L4.Proto.Dataspace,
                                        size_mb * 1024 * 1024,
                                        mem_flags, align):m("rw");
  end

  local caps = {
    net  = vnet;
    vbus = vbus;
    ram  = vm_ram;
  };

  if options.jdb then
    caps["jdb"] = L4.Env.jdb
  end

  if options.ext_args then
    for _,v in ipairs(options.ext_args) do
      cmdline[#cmdline+1] = v
    end
  end

  local opts = {
    log  = options.log or l.log_fab:create(L4.Proto.Log, "vm" .. nr, "w",
                                           keyb_shortcut);
    caps = table_override(caps, options.ext_caps or {});
  };

  if scheduler then
    opts["scheduler"] = scheduler;
  else
    set_sched(opts, prio, cpus);
  end

  if type(options.mon) == 'string' then
    -- assume 'mon' is the name of a server binary which implements the uvmm
    -- CLI interface
    mon = l:new_channel()

    l:start({
      scheduler = opts.scheduler;
      log = l.log_fab:create(L4.Proto.Log, "mon" .. nr),
      caps = { mon = mon:svr() }
    }, "rom/" .. options.mon)

    opts.caps["mon"] = mon
  elseif options.mon ~= false then
    opts.caps["mon"] = l.log_fab:create(L4.Proto.Log, "mon" .. nr, "g");
  end

  return l:startv(opts, "rom/uvmm", table.unpack(cmdline));
end

return _ENV
