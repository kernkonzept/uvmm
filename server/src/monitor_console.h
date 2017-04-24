/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/cxx/ipc_server>
#include <l4/cxx/ipc_stream>

#include <l4/sys/vcon>

#include "cpu_dev_array.h"
#include "device.h"
#include "guest.h"

class Monitor_console
: private L4::Server_object_t<L4::Vcon>,
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

  template<typename REG>
  void register_obj(REG *registry)
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

  int dispatch(l4_umword_t, L4::Ipc::Iostream &)
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
    return 0;
  }

private:
  L4::Cap<L4::Vcon> _con;
  Vdev::Device_lookup *_devices;
};
