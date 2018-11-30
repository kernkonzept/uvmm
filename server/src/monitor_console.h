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

public:
  Monitor_console(L4::Cap<L4::Vcon> con, Vmm::Generic_guest *guest)
  : _con(con), _guest(guest)
  {
  }

  template<typename REG>
  void register_obj(REG *registry)
  {
    _con->bind(0, L4Re::chkcap(registry->register_irq_obj(this)));
    // we want something like fprintf(_con, ...) here
    printf("Monitor UP (printf'ing to wrong channel)\n");
    prompt();
  }

  void prompt()
  {
    const char *s = "monitor> ";
    _con->write(s, strlen(s));
  }

  int dispatch(l4_umword_t, L4::Ipc::Iostream &)
  {
    //handle_input();
    //char buf[100];
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
                _guest->show_state_registers();
                break;
              case 'i':
                _guest->show_state_interrupts();
                break;
              default:
                printf("Monitor: Unknown cmd\n");
                break;
              };
          }
        _con->write("\n", 1);
        prompt();
      }
    while (r > 0);
    return 0;
  }

private:
  L4::Cap<L4::Vcon> _con;
  Vmm::Generic_guest *_guest;
};
