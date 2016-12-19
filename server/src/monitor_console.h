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

#include "guest.h"
#include "vcpu_array.h"

class Monitor_console
: private L4::Server_object_t<L4::Vcon>,
  public cxx::Ref_obj
{
  FILE *_f;

public:
  Monitor_console(const char * const capname, L4::Cap<L4::Vcon> con,
                  Vmm::Guest *guest, cxx::Ref_ptr<Vmm::Vcpu_array> const &cpus)
  : _con(con), _guest(guest), _cpus(cpus)
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
                _cpus->show_state_registers(_f);
                break;
              case 'i':
                fputc('\n', _f);
                for (unsigned i = 0; i < Vmm::Vcpu_array::Max_cpus; ++i)
                  if (_cpus->vcpu_exists(i))
                    _guest->show_state_interrupts(_f, _cpus->vcpu(i));
                break;
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
  Vmm::Guest *_guest;
  cxx::Ref_ptr<Vmm::Vcpu_array> _cpus;
};
