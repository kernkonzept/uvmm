/*
 * Copyright (C) 2019, 2022-2023 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <l4/cxx/exceptions>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/sys/cxx/ipc_epiface>
#include <l4/sys/err.h>
#include <l4/sys/ipc.h>
#include <l4/sys/vcon.h>
#include <l4/sys/vcon>

#include "debug.h"
#include "uvmm_cli.h"
#include "vm.h"
#include "monitor/monitor.h"
#include "monitor/monitor_args.h"
#include "monitor/dbg_enable_cmd_handler.h"

namespace {

class Cmd_control : public L4::Irqep_t<Cmd_control>
{
  enum { Vcon_buf_sz = 100 };

  struct Named_cmd_handler
  {
    Named_cmd_handler(Monitor::Cmd *cmd, char const *name)
    : cmd(cmd),
      name(name)
    {}

    Monitor::Cmd *cmd;
    char const *name;
  };

public:
  class Help : public Monitor::Cmd
  {
  public:
    Help()
    { register_toplevel("help"); }

    char const *help() const override
    { return "Print help"; }

    void usage(FILE *f) const override
    {
      fprintf(f, "%s\n"
                 "* 'help': list descriptions of all available commands\n"
                 "* 'help <cmd>': show usage message for <cmd>\n",
              help());
    }

    void complete(FILE *f, Monitor::Completion_request *compl_req) const override
    {
      for (auto const &handler : Cmd_control::get()->_cmd_handlers)
        compl_req->complete(f, handler.name);
    }

    void exec(FILE *f, Monitor::Arglist *args) override
    {
      if (args->empty())
        {
          for (auto const &handler : Cmd_control::get()->_cmd_handlers)
            fprintf(f, "%-12s  %s\n", handler.name, handler.cmd->help());
        }
      else
        {
          auto cmd_arg = args->pop();

          char const *cmd = cmd_arg.get();
          size_t cmd_len = strlen(cmd);

          auto *handler = Cmd_control::get()->find_cmd_handler(cmd, cmd_len);

          if (!handler)
            fprintf(f, "Unknown command %.*s\n", static_cast<int>(cmd_len), cmd);
          else
            handler->usage(f);
        }
    }
  };

  class Verbose : public Monitor::Cmd
  {
  public:
    Verbose()
    { register_toplevel("verbose"); }

    char const *help() const override
    { return "Display/Adjust verbosity"; }

    void usage(FILE *f) const override
    {
      fprintf(f, "%s\n"
                 "* 'verbose show <component>': display level for some component\n"
                 "* 'verbose set <component> <level>': set level for some component\n"
                 "where: <level> = (quiet|warn|info|trace)\n"
                 "and:   <component> = (all|uest|core|cpu|mmio|irq|dev)\n",
              help());
    }

    void complete(FILE *f, Monitor::Completion_request *compl_req) const override
    {
      switch (compl_req->count() + compl_req->trailing_space())
        {
        case 0:
        case 1:
          compl_req->complete(f, {"show", "set"});
          break;
        case 2:
          {
            auto subcmd = compl_req->pop();

            if (subcmd == "show")
              complete_components(f, compl_req);
            else if (subcmd == "set")
              {
                complete_components(f, compl_req);
                compl_req->complete(f, "all");
              }
          }
          break;
        case 3:
          {
            auto subcmd = compl_req->pop();
            auto component = compl_req->pop();

            if (subcmd == "set"
                && (component == "all" || component_valid(component.get())))
              complete_verbosity_levels(f, compl_req);
          }
          break;
        }
    }

    void exec(FILE *f, Monitor::Arglist *args) override
    {
      auto subcmd = args->pop();

      auto component = args->pop<std::string>("Missing component identifier");

      if (subcmd == "show")
        {
          if (!component_valid(component.c_str()))
            Monitor::argument_error("Invalid component specifier");

          char const *v;
          if (Dbg::get_verbosity(component.c_str(), &v) == L4_EOK)
            {
              fprintf(f, "%s\n", v);
              return;
            }
        }
      else if (subcmd == "set")
        {
          bool all = strcmp(component.c_str(), "all") == 0;

          if (!all && !component_valid(component.c_str()))
            Monitor::argument_error("Invalid component specifier");

          auto verbosity_level = args->pop<std::string>(
            "Missing verbosity level identifier");

          if (!verbosity_level_valid(verbosity_level.c_str()))
            Monitor::argument_error("Invalid verbosity level specifier");

          bool success;

          if (all)
            success = Dbg::set_verbosity(verbosity_level.c_str()) == L4_EOK;
          else
            {
              auto verbosity_cmd =
                component.c_str() + std::string("=") + verbosity_level.c_str();

              success = Dbg::set_verbosity(verbosity_cmd.c_str()) == L4_EOK;
            }

          if (!success)
            Monitor::argument_error("Failed to set verbosity");
        }
      else
        Monitor::argument_error("Invalid subcommand");
    }

  private:
    static bool component_valid(char const *component)
    {
      auto const *c = Dbg::valid_components();

      while (*c)
        {
          if (strcmp(component, *c++) == 0)
            return true;
        }

      return false;
    }

    static bool verbosity_level_valid(char const *verbosity_level)
    {
      auto const *v = Dbg::valid_verbosity_levels();

      while (*v)
        {
          if (strcmp(verbosity_level, *v++) == 0)
            return true;
        }

      return false;
    }

    static void complete_components(FILE *f,
                                    Monitor::Completion_request *compl_req)
    {
      auto const *c = Dbg::valid_components();

      while (*c)
        compl_req->complete(f, *c++);
    }

    static void complete_verbosity_levels(FILE *f,
                                          Monitor::Completion_request *compl_req)
    {
      auto const *v = Dbg::valid_verbosity_levels();

      while (*v)
        compl_req->complete(f, *v++);
    }
  };

  static Cmd_control *get()
  {
    static Cmd_control mon("mon", "monitor> ");
    return &mon;
  }

  ~Cmd_control()
  {
    if (_f)
      fclose(_f);
  }

  // true if monitoring was enabled during startup
  bool enabled() const
  { return _con.is_valid(); }

  void bind(L4::Registry_iface *registry)
  {
    if (enabled())
      _con->bind(0, L4Re::chkcap(registry->register_irq_obj(this),
                                 "Register monitor console IRQ."));
  }

  void add_cmd_handler(Monitor::Cmd *cmd, char const *name)
  {
    if (!enabled())
      return;

    auto it = _cmd_handlers.begin();

    while (it != _cmd_handlers.end())
      {
        if (strcmp(name, it->name) < 0)
          break;

        ++it;
      }

    _cmd_handlers.insert(it, Named_cmd_handler(cmd, name));
  }

  void remove_cmd_handler(Monitor::Cmd *cmd)
  {
    for (auto it = _cmd_handlers.begin(); it != _cmd_handlers.end(); ++it)
      {
        if (it->cmd == cmd)
          {
            _cmd_handlers.erase(it);
            return;
          }
      }
  }

  Monitor::Cmd *find_cmd_handler(char const *name, size_t name_len) const
  {
    for (auto &handler : _cmd_handlers)
      {
        if (strlen(handler.name) == name_len
            && strncmp(handler.name, name, name_len) == 0)
          {
            return handler.cmd;
          }
      }

    return nullptr;
  }

  void handle_irq()
  {
    std::string line;
    if (!get_line(&line))
      return;

    if (line.back() == (char)Uvmm_cli::PROTO_COMPL_REQ)
      handle_completion(line.substr(0, line.size() - 1).c_str());
    else
      handle_cmd(line.c_str());
  }

private:
  Cmd_control(char const *capname, char const *prompt)
  : _f(nullptr),
    _prompt(prompt),
    _con(L4Re::Env::env()->get_cap<L4::Vcon>(capname))
  {
    if (!enabled())
      return; // no monitoring requested

    _f = fopen(capname, "w+");
    if (!_f)
      {
        Err().printf("Could not open command control '%s'\n", capname);
        L4Re::throw_error(-L4_ENOENT, "Open channel to command control.");
      }

    l4_vcon_attr_t attr;
    if (l4_error(_con->get_attr(&attr)) != L4_EOK)
      {
        Err().printf("Failed to determine command control attributes, "
                     "CLI interface may be disabled\n");
        _show_prompt = false;
      }
    else
      {
        _show_prompt =
          !(attr.l_flags & Uvmm_cli::ENABLED);
      }
  }

  bool get_line(std::string *line)
  {
    // read more data
    char buf[Vcon_buf_sz];

    for (;;)
      {
        int read_sz = _con->read(buf, Vcon_buf_sz);

        if (read_sz < 0)
          {
            Err().printf("Failed to read data");
            return false;
          }

        if (read_sz > Vcon_buf_sz)
          {
            _read_buf.append(buf, Vcon_buf_sz);
          }
        else
          {
            _read_buf.append(buf, read_sz);
            break;
          }
      }

    // check if a line is buffered
    char const *newline = reinterpret_cast<char const *>(
      memchr(_read_buf.data(), '\n', _read_buf.size()));

    if (!newline)
      return false;

    *line = std::string(_read_buf.data(), newline - _read_buf.data());
    _read_buf = std::string(newline + 1);

    return true;
  }

  void handle_cmd(char const *cmd_line)
  {
    char *delim = strchrnul(cmd_line, ' ');

    size_t cmd_len = delim - cmd_line;
    auto *handler = find_cmd_handler(cmd_line, cmd_len);

    if (handler)
      {
        Monitor::Arglist arglist(*delim ? delim + 1 : delim);

        try
          {
            handler->exec(_f, &arglist);
          }
        catch (L4::Runtime_error const &e)
          {
            fprintf(_f, "Command execution failed");

            char const *msg = e.extra_str();
            if (msg)
              fprintf(_f, ": %s", msg);

            fprintf(_f, "\n\n%s\n", handler->help());
          }
      }
    else
      fprintf(_f, "Monitor: Unknown cmd %.*s\n", (int)cmd_len, cmd_line);

    end_transmission();
  }

  void handle_completion(char const *cmd_line)
  {
    // find the position of the first and last character of the last word
    // on the command line (this is the word for which we want to produce
    // completions)
    int end_last = strlen(cmd_line);

    int beg_last = end_last - 1;
    while (beg_last >= 0 && cmd_line[beg_last] != ' ')
      --beg_last;
    ++beg_last;

    if (beg_last == 0)
      {
        // if there is only one word, complete it using all registered commands
        for (auto const &handler : _cmd_handlers)
          {
             if (end_last <= (int)(strlen(handler.name))
                 && strncmp(cmd_line + beg_last, handler.name, end_last) == 0)
               {
                 fprintf(_f,
                         "%s%c",
                         handler.name,
                         (char)Uvmm_cli::PROTO_COMPL_SEP);
               }
          }
      }
    else
      {
        // find the position of the last character of the current commands name
        int end_first = 1;
        while (cmd_line[end_first] != ' ')
          ++end_first;

        // look up a handler corresponding to this command name and if such a
        // handler exists, let it complete the rest of the command line
        auto *handler = find_cmd_handler(cmd_line, end_first);
        if (handler)
          {
            // find the beginning of additional arguments to the command
            // and pass them to the handlers completion method
            int beg_sub = end_first;
            while (beg_sub < end_last && cmd_line[beg_sub] == ' ')
              ++beg_sub;

            Monitor::Completion_request compl_req(cmd_line + beg_sub);
            handler->complete(_f, &compl_req);
          }
      }

     end_transmission();
  }

  void end_transmission()
  {

    if (_show_prompt)
      fprintf(_f, "%s", _prompt);
    else
      fputc((char)Uvmm_cli::PROTO_EOT, _f);

    fflush(_f);
  }

  FILE *_f;
  char const *_prompt;
  bool _show_prompt;
  std::string _read_buf;

  L4::Cap<L4::Vcon> _con;
  std::vector<Named_cmd_handler> _cmd_handlers;
};

} // namespace

namespace Monitor {

void
Cmd::register_toplevel(char const *name)
{ Cmd_control::get()->add_cmd_handler(this, name); }

void
Cmd::unregister_toplevel()
{ Cmd_control::get()->remove_cmd_handler(this); }

Cmd::~Cmd()
{ unregister_toplevel(); }

void
enable_cmd_control(Vmm::Vm *vm)
{
  static Cmd_control::Help help;
  static Cmd_control::Verbose verbose;

  static Dbg_enable_cmd_handler<Guest_debugger_support>
  dbg_enable_cmd_handler(vm);

  Cmd_control::get()->bind(vm->vmm()->registry());
}

bool
cmd_control_enabled()
{ return Cmd_control::get()->enabled(); }

}
