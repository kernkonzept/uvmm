/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once


#include <l4/cxx/ipc_server>
#include <l4/cxx/ipc_stream>

#include <l4/sys/vcon>

class Monitor_console : private L4::Server_object_t<L4::Vcon>
{
  FILE *_f;

public:
  Monitor_console(const char * const capname, L4::Cap<L4::Vcon> con, Vmm::Generic_guest *guest)
  : _con(con), _guest(guest)
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
        char cmd;
        r = _con->read(&cmd, 1);
        if (r == 1)
          {
            switch (cmd)
              {
              case 'r':
                fputc('\n', _f);
                _guest->show_state_registers(_f);
                break;
              case 'i':
                fputc('\n', _f);
                _guest->show_state_interrupts(_f);
                break;
              case '\n':
              case '\r':
              case '\b':
                break;
              default:
                fprintf(_f, "\nMonitor: Unknown cmd\n");
                break;
              };
          }

        prompt();
      }
    while (r > 0);
    return 0;
  }

private:
  L4::Cap<L4::Vcon> _con;
  Vmm::Generic_guest *_guest;
};
