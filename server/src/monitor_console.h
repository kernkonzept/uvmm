/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/sys/cxx/ipc_epiface>

#include <l4/sys/vcon>
#include <l4/re/event_enums.h>

#include "cpu_dev_array.h"
#include "device.h"
#include "guest.h"

#include "virtio_input_power.h"

class Monitor_console
: public L4::Irqep_t<Monitor_console>,
  public cxx::Ref_obj
{
  FILE *_f;

public:
  Monitor_console(const char * const capname, L4::Cap<L4::Vcon> con,
                  Vdev::Device_lookup *devs)
  : _con(con), _devices(devs)
  {
    _f = fopen(capname, "w+");
    if (!_f)
      {
        Err().printf("Could not open monitor console '%s'\n", capname);
        L4Re::chksys(-L4_ENOENT);
      }
  }

  ~Monitor_console()
  {
    fclose(_f);
  }

  static cxx::Ref_ptr<Monitor_console> create(Vdev::Device_lookup *devs)
  {
    const char * const capname = "mon";
    auto mon_con_cap = L4Re::Env::env()->get_cap<L4::Vcon>(capname);
    if (!mon_con_cap)
      return nullptr;

    auto moncon = cxx::make_ref_obj<Monitor_console>(capname, mon_con_cap, devs);
    moncon->register_obj(devs->vmm()->registry());

    return moncon;
  }

  void register_obj(L4::Registry_iface *registry)
  {
    _con->bind(0, L4Re::chkcap(registry->register_irq_obj(this)));
    fprintf(_f, "VMM Monitor Console\n");
    prompt();
  }

  void prompt()
  {
    fprintf(_f, "monitor> ");
    fflush(_f);
  }

  void handle_irq()
  {
    int r;

    do
      {
        bool print_prompt = false;
        char cmd;
        r = _con->read_with_flags(&cmd, 1);

        // Ignore any characters tagged with break
        if (r & L4_VCON_READ_STAT_BREAK)
          {
            brk = true;
            continue;
          }

        if (r >= 1)
          {
            if (brk)
              {
#ifdef VIRTIO_POWER
                Vdev::do_inject_sysreq_event(cmd);
#endif
                brk = false;
                continue;
              }

            print_prompt = true;
            switch (cmd)
              {
              case 'r':
                fputc('\n', _f);
                _devices->cpus()->show_state_registers(_f);
                break;
              case 'i':
                {
                  fputc('\n', _f);
                  for (auto &cpu : *_devices->cpus().get())
                    if (cpu)
                      _devices->vmm()->show_state_interrupts(_f, cpu->vcpu());
                  break;
                }
              case 't': Dbg::set_verbosity(Dbg::Trace | Dbg::Info | Dbg::Warn); break;
              case 'T': Dbg::set_verbosity(Dbg::Info | Dbg::Warn); break;
              case '\r':
              case '\b':
                print_prompt = false;
                break;
              case '\n':
                break;
              default:
                fprintf(_f, "\nMonitor: Unknown cmd %x\n", cmd);
                break;
              };
          }

        if (print_prompt)
          prompt();
      }
    while (r > 0);
  }

private:
  bool brk = false;
  L4::Cap<L4::Vcon> _con;
  Vdev::Device_lookup *_devices;
};
