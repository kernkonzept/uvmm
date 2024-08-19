local L4 = require "L4";

local l = L4.Loader.new({mem = L4.Env.user_factory});
loader = l;

function new_sched(prio, cpus)
  return  L4.Env.user_factory:create(L4.Proto.Scheduler, prio + 10, prio, cpus);
end

function start_io(busses, opts)
  local caps = {
    sigma0 = L4.cast(L4.Proto.Factory, L4.Env.sigma0):create(L4.Proto.Sigma0);
    icu    = L4.Env.icu;
    iommu  = L4.Env.iommu;
  };

  local files = "";

  for k, v in pairs(busses) do
    local c = l:new_channel();
    busses[k] = c
    caps[k] = c:svr();
    files = files .. " rom/" .. k .. ".vbus";
  end

  return l:start({
    log = { "io", "red" },
    caps = caps
  }, "rom/io " .. opts .. files)
end

-- Creates a scheduler proxy and writes it into the `opts` table.
--
-- Four cases happen here:
--  A) No prio and no cpus: No scheduler proxy created.
--  B) A prio, but no cpus: Create a scheduler proxy with only a priority limit.
--  C) No Prio, but cpus: Create a scheduler proxy with default prio and cpus
--     limit.
--  D) A prio and cpus: Create a scheduler proxy with given limits.
local function set_sched(opts, prio, cpus)
  if cpus == nil and prio == nil then
    return
  end

  if prio == nil then
    -- Default to zero to use the L4Re Default_thread_prio
    prio = 0
  end

  local sched = new_sched(prio, cpus);
  opts["scheduler"] = sched;
end

function start_virtio_switch(ports, prio, cpus, switch_type)
  local caps = {};
  local switch = l:new_channel();

  local opts = {
    log = { "switch", "Blue" },
    caps = { svr = switch:svr() };
  };

  set_sched(opts, prio, cpus);
  if switch_type == "switch" then
    local port_count = 0;
    for k, v in pairs(ports) do
      port_count = port_count + 1;
    end
    svr = l:start(opts, "rom/l4vio_switch -v -m -p " .. port_count );

    for k, v in pairs(ports) do
       ports[k] = L4.cast(L4.Proto.Factory, switch):create(0, "ds-max=4", "name=" .. k)
    end
  else
    svr = l:start(opts, "rom/l4vio_net_p2p");

    for k, v in pairs(ports) do
      ports[k] = L4.cast(L4.Proto.Factory, switch):create(0, "ds-max=4");
    end
  end

  return svr;
end

function start_vm(options)
  local nr      = options.id;
  local size_mb = 0;
  local vbus    = options.vbus;
  local vnet    = options.net;
  local prio    = options.prio;
  local cpus    = options.cpus;

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

  if options.ext_caps then
    for k, v in pairs(options.ext_caps) do
      caps[k] = v
    end
  end

  local opts = {
    log  = options.log or l.log_fab:create(L4.Proto.Log, "vm" .. nr, "w",
                                           keyb_shortcut);
    caps = caps;
  };

  set_sched(opts, prio, cpus);

  if type(options.mon) == 'string' then
    -- assume 'mon' is the name of a server binary which implements the uvmm
    -- CLI interface
    mon = l:new_channel()

    l:start({
      scheduler = opts.scheduler;
      log = l.log_fab:create(L4.Proto.Log, "mon" .. nr),
      caps = { mon = mon:svr() }
    }, "rom/" .. options.mon)

    caps["mon"] = mon
  elseif options.mon ~= false then
    caps["mon"] = l.log_fab:create(L4.Proto.Log, "mon" .. nr, "g");
  end

  return l:startv(opts, "rom/uvmm", table.unpack(cmdline));
end

return _ENV
