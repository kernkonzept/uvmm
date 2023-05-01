/*
 * Copyright (C) 2019-2020 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/br_manager>
#include <l4/re/util/icu_svr>
#include <l4/re/util/object_registry>
#include <l4/re/util/vcon_svr>
#include <l4/sys/err.h>
#include <l4/sys/semaphore>
#include <l4/sys/vcon.h>
#include <l4/sys/vcon>

#include <readline/history.h>
#include <readline/readline.h>

#include "uvmm_cli.h"

/**
 * Uvmm CLI server.
 *
 * See `uvmm_cli.h` for an explanation of the protocol used to exchange
 * commands and completions with uvmm.
 */

/*
 * Two threads will run inside a server running this program, the main thread
 * and the "readline-thread". The main thread runs the server loop after
 * registering an object that implements the vcon protocol over which uvmm
 * exchanges data with the server. The readline thread implements the main
 * readline loop. In principle, this second thread could have been avoided by
 * utilizing readlines asynchronous interface but it turns out that this does
 * not work well together with e.g. history search.
 *
 * Cooperation and synchronisation between these two threads works as follows:
 * Once the user has entered a line via the readline interface, the readline
 * thread will preprocess this line, append it to the command history and then
 * copy it into a buffer (`Uvmm_cli_vcon::_send_buf`) that is shared between
 * both threads. It will then trigger an irq that signals uvmm to start
 * receiving command data from the server and subsequently block on a semaphore
 * (`Uvmm_cli_vcon::_sem`). The thread will continue to block on this
 * semaphore until uvmm has read the issued command and sent back the complete
 * command output.
 *
 * Inside an irq handler uvmm will issue vcon read requests which will lead to
 * the execution of `Uvmm_cli_vcon::vcon_read` inside the main thread. We make
 * no assumptions about whether uvmm will read the whole command at once or in
 * blocks (i.e. `Uvmm_cli_vcon::vcon_read` may run arbitrarily often). Once
 * uvmm has read the whole command, a flag which indicates that uvmm command
 * output is expected (`Uvmm_cli_vcon::_ready_to_receive`) is set. This is
 * done such as to prevent any possibility of spurious vcon writes coming from
 * uvmm at other points in time interfering with the command output receive
 * buffer (`Uvmm_cli_vcon::_receive_buf`). Receiving the command output, again
 * possibly in blocks, happens inside `Uvmm_cli_vcon::vcon_write` running in
 * the main thread. When a special terminating character sequence is read (see
 * `uvmm_cli.h`), `Uvmm_cli_vcon::_ready_to_receive` is set to `false` and
 * `Uvmm_cli_vcon::_sem` is incremented such that the readline thread can wake
 * up, read the command output from `Uvmm_cli_vcon::_receive_buf`, write it to
 * stdout and start the whole process anew.
 *
 * This procedure ensure that readline prompt will only become active again
 * after the complete output of a command has been produced and sent back to
 * the server.
 */

namespace {

class Uvmm_cli_vcon
: public L4Re::Util::Vcon_svr<Uvmm_cli_vcon>,
  public L4Re::Util::Icu_cap_array_svr<Uvmm_cli_vcon>,
  public L4::Epiface_t<Uvmm_cli_vcon, L4::Vcon>
{
public:
  static Uvmm_cli_vcon *get()
  {
    static Uvmm_cli_vcon cons;
    return &cons;
  }

  unsigned vcon_read(char *buf, unsigned size)
  {
    std::lock_guard<std::mutex> lock(_send_mutex);

    if (_send_buf.empty())
      return L4_VCON_READ_STAT_DONE;

    if (size == 0)
      return 0;

    if (size < _send_buf.size())
      {
        memcpy(buf, _send_buf.data(), size);

        _send_buf = _send_buf.substr(size);
      }
    else
      {
        memcpy(buf, _send_buf.data(), _send_buf.size());
        size = _send_buf.size() | L4_VCON_READ_STAT_DONE;

        _send_buf.clear();
        _ready_to_receive = true;
      }

    return size;
  }

  void vcon_write(const char *buf, unsigned size)
  {
    if (!_ready_to_receive || size == 0)
      return;

    std::lock_guard<std::mutex> lock(_receive_mutex);

    char const *eot = reinterpret_cast<char const *>(
      memchr(buf, (char)Uvmm_cli::PROTO_EOT, size));

    if (eot)
      {
        _receive_buf << std::string(buf, eot);
        _ready_to_receive = false;
        _sem->up();
      }
    else
      {
        _receive_buf << std::string(buf, buf + size);
      }
  }

  int vcon_get_attr(l4_vcon_attr_t *attr)
  {
    attr->l_flags = Uvmm_cli::ENABLED;
    attr->o_flags = attr->i_flags = 0;
    return L4_EOK;
  }

  void send(std::string const &buf)
  { _send(buf); }

  void complete(std::string const &buf)
  { _send(buf, true); }

  std::string receive()
  {
    std::lock_guard<std::mutex> lock(_receive_mutex);

    assert(!_ready_to_receive);

    std::string ret(_receive_buf.str());
    _receive_buf.str("");

    return ret;
  }

private:
  Uvmm_cli_vcon() : Icu_cap_array_svr<Uvmm_cli_vcon>(1, &_irq),
                   _sem(L4Re::Util::make_unique_cap<L4::Semaphore>()),
                   _ready_to_receive(false)
  {
    L4Re::chkcap(_sem, "semaphore capability slot valid");

    L4Re::chksys(L4Re::Env::env()->factory()->create(_sem.get()),
                 "create semaphore kernel object");
  }

  void _send(std::string const &buf, bool complete = false)
  {
    {
      std::lock_guard<std::mutex> lock(_send_mutex);

      assert(_send_buf.empty());

      _send_buf = buf;
      if (complete)
        _send_buf += (char)Uvmm_cli::PROTO_COMPL_REQ;
      _send_buf += '\n';
    }

    _irq.trigger();

    _sem->down();
  }

  std::string _send_buf;
  std::stringstream _receive_buf;
  L4Re::Util::Icu_cap_array_svr<Uvmm_cli_vcon>::Irq _irq;

  L4Re::Util::Unique_cap<L4::Semaphore> _sem;
  std::mutex _send_mutex; /// synchronises access to _send_buf
  std::mutex _receive_mutex; /// synchronises access to _receive_buf
  bool _ready_to_receive;
};

class Readline_loop
{
public:
  static Readline_loop *get()
  {
    static Readline_loop rl;
    return &rl;
  }

  void run(char const *prompt)
  {
    // readline loop
    for (;;)
      {
        // read line
        char *line = readline(const_cast<char *>(prompt));

        // ignore EOF or empty line
        if (!line)
          {
            std::cout << '\n';
            continue;
          }

        std::string line_preprocessed(preprocess_command(line));

        if (line_preprocessed.empty())
          continue;

        // add to history, mimicking the 'ignoreboth' HISTOCONTROL setting
        if (strlen(line) > 0 && line[0] != ' ')
          {
            HIST_ENTRY **hist_list = history_list();
            if (hist_list)
              {
                HIST_ENTRY *hist = hist_list[history_length - 1];
                if (!hist || strcmp(line, hist->line) != 0)
                  add_history(line);
              }
            else
              {
                add_history(line);
              }
          }

        free(line);

        // send to uvmm
        Uvmm_cli_vcon::get()->send(line_preprocessed);

        // receive from uvmm
        std::cout << Uvmm_cli_vcon::get()->receive();
      }
  }

private:
  Readline_loop()
  {
    rl_attempted_completion_function = attempt_completion;
    rl_completer_word_break_characters = const_cast<char *>(" \t\n");
  }

  static char *generate_completion(const char *, int state)
  {
    static decltype(_completions_buf.size()) i;

    if (!state)
      i = 0;

    while (i < _completions_buf.size())
      return strdup(_completions_buf[i++].c_str());

    return nullptr;
  }

  static char **attempt_completion(char const *, int, int)
  {
    rl_attempted_completion_over = 1;

    // send completion request to uvmm
    std::string to_complete(preprocess_completion(
      std::string(rl_line_buffer, rl_line_buffer + rl_point)));

    Uvmm_cli_vcon::get()->complete(to_complete);

    // parse completions
    std::string completed(Uvmm_cli_vcon::get()->receive());
    std::stringstream ss(completed.substr(0, completed.size() - 1));

    _completions_buf.clear();

    std::string completion;
    while (std::getline(ss, completion, (char)Uvmm_cli::PROTO_COMPL_SEP))
      {
        if (!completion.empty())
          _completions_buf.emplace_back(completion);
      }

    return rl_completion_matches(nullptr, generate_completion);
  }

  static std::string trim_left(std::string const &line)
  {
    auto beg = std::find_if(
      line.begin(), line.end(), [](int c){ return c != ' '; });

    return std::string(beg, line.end());
  }

  static std::string trim_right(std::string const &line)
  {
    auto end = std::find_if(
      line.rbegin(), line.rend(), [](int c){ return c != ' '; }).base();

    return std::string(line.begin(), end);
  }

  static std::string trim(std::string const &line)
  {
    auto it = std::find_if(
      line.begin(), line.end(), [](int c){ return c != ' '; });

    if (it == line.end())
      return "";

    return trim_right(trim_left(line));
  }

  static std::string compress(std::string const &line)
  {
    if (line.empty())
      return line;

    std::stringstream ss(line), ret;

    std::string::size_type beg = 0;
    while (beg < line.size())
      {
        auto end = beg + 1;

        while (end < line.size() && line[end] != ' ')
          ++end;

        ret << (beg == 0 ? "" : " ") << line.substr(beg, end - beg);

        beg = end + 1;
        while (beg < line.size() && line[beg] == ' ')
          ++beg;
      }

    if (line.back() == ' ')
      ret << ' ';

    return ret.str();
  }

  static std::string preprocess_command(std::string const &line)
  { return compress(trim(line)); }

  static std::string preprocess_completion(std::string const &line)
  { return compress(trim_left(line)); }

  static std::vector<std::string> _completions_buf;
};

std::vector<std::string> Readline_loop::_completions_buf;

void run_readline(std::string prompt)
{ Readline_loop::get()->run(prompt.c_str()); }

} // namespace

int main(int argc, char **argv)
{
  if (argc > 2)
    {
      std::cerr << "Usage: " << argv[0] << " [PROMPT]\n";
      return EXIT_FAILURE;
    }

  try
    {
      // start readline thread
      std::thread readline_thread(run_readline,
                                  argc == 2 ? argv[1] : "monitor> ");

      // create registry
      L4Re::Util::Registry_server<L4Re::Util::Br_manager_hooks> registry_server;

      registry_server.registry()->register_obj(Uvmm_cli_vcon::get(), "mon");

      // start server loop
      registry_server.loop();
    }
  catch (std::exception const &e)
    {
      std::cerr << e.what() << '\n';
      return EXIT_FAILURE;
    }
  catch (...)
    {
      std::cerr
        << "An unknown exception occurred while running the readline loop\n";
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}
