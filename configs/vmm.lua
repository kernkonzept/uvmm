local L4 = require "L4";

local l = L4.Loader.new({factory = L4.Env.factory, mem = L4.Env.user_factory});
loader = l;

function new_sched(prio, cpus)
  return l.sched_fab:create(L4.Proto.Scheduler, prio + 10, prio, cpus);
end

function start_io(busses, opts)
  local caps = {
    sigma0 = L4.cast(L4.Proto.Factory, L4.Env.sigma0):create(L4.Proto.Sigma0);
    icu    = L4.Env.icu;
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

local function set_sched(opts, prio, cpus)
  if prio ~= nil then
    local sched = new_sched(prio, cpus);
    opts["scheduler"] = sched;
  end
end

function start_virtio_switch(ports, prio, cpus)
  local caps = {};
  local switch = l:new_channel();

  local opts = {
    log = { "switch", "Blue" },
    caps = { svr = switch:svr() };
  };

  set_sched(opts, prio, cpus);
  svr = l:start(opts, "rom/l4vio_net_p2p");

  for k, v in pairs(ports) do
    ports[k] = L4.cast(L4.Proto.Factory, switch):create(0, 4);
  end

  return svr;
end

function start_vm(options)
  local nr      = options.id;
  local size_mb = options.mem or 16;
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
    cmdline[#cmdline+1] = "-d" .. options.fdt;
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

  local mem_flags = L4.Mem_alloc_flags.Continuous
                    | L4.Mem_alloc_flags.Pinned
                    | L4.Mem_alloc_flags.Super_pages;

  local caps = {
    net  = vnet;
    vbus = vbus;
    ram  = L4.Env.user_factory:create(L4.Proto.Dataspace,
                                      size_mb * 1024 * 1024,
                                      mem_flags, align):m("rws");
  };

  if options.mon ~= false then
    caps["mon"] = l.log_fab:create(L4.Proto.Log, "mon" .. nr, "g");
  end

  if options.jdb then
    caps["jdb"] = L4.Env.jdb
  end

  if options.ext_args then
    for _,v in ipairs(options.ext_args) do
      cmdline[#cmdline+1] = v
    end
  end

  local opts = {
    log  = l.log_fab:create(L4.Proto.Log, "vm" .. nr, "w", keyb_shortcut);
    caps = caps;
  };

  set_sched(opts, prio, cpus);
  return l:startv(opts, "rom/uvmm", table.unpack(cmdline));
end

return _ENV
