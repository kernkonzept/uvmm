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

#include "cpu_dev_array.h"
#include "device.h"
#include "guest.h"

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
        r = _con->read(&cmd, 1);
        if (r >= 1)
          {
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
                  auto cpus = _devices->cpus();
                  for (unsigned i = 0; i < Vmm::Cpu_dev_array::Max_cpus; ++i)
                    if (cpus->vcpu_exists(i))
                      _devices->vmm()->show_state_interrupts(_f, cpus->vcpu(i));
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
                fprintf(_f, "\nMonitor: Unknown cmd\n");
                break;
              };
          }

        if (print_prompt)
          prompt();
      }
    while (r > 0);
  }

private:
  L4::Cap<L4::Vcon> _con;
  Vdev::Device_lookup *_devices;
};
