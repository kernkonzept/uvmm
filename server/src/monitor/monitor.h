/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/cxx/ipc_epiface>

namespace Monitor {

/// Monitor console state indicator
enum : bool {
  /// `True` if monitor console support has been enabled during compilation
#ifdef CONFIG_MONITOR
  Enabled = true
#else
  Enabled = false
#endif
};

/**
 * Abstract monitor console command interface.
 *
 * This class provides a common interface implemented by all monitor console
 * command handlers.
 */
class Cmd
{
public:
  /**
   * Return command help message.
   *
   * \return The help message as a C-string.
   *
   * The value returned by this function is displayed alongside the command
   * name in the output of the `help` command and should only consist of
   * a single short line of text describing the action performed by the command.
   */
  virtual char const *help() const = 0;

  /**
   * Complete partial arguments.
   *
   * \param f     Stream to which completions are to be written.
   *
   * \param args  Command line arguments to be completed.
   *
   * This method should examine whether there exist one or several suitable
   * completions for the partial arguments to the command implemented by this
   * monitor passed via `args`. If so, these completions should be written to
   * `f` in arbitrary order, separated by newlines (with an optional trailing
   * newline).  Otherwise this method should do nothing. When `args` is an
   * empty string, all possible subcommands should be output this way.
   */
  virtual void complete(FILE *f, char const *args) const
  { (void)f; (void)args; }

  /**
   * Invoke command.
   *
   * \param f     Stream to which command output (both regular output and
   *              errors) should be written. The command output should always
   *              end with a final newline, unless no output is produced to
   *              begin with.
   *
   * \param args  Arguments passed to the command, if no arguments where passed,
   *              this is an empty C-string, otherwise this is a list of
   *              arguments guaranteed to be separated by single spaces (with no
   *              leading or trailing whitespace). In case of invalid arguments,
   *              an error message should be written to `f`.
   *
   * This method is called when the implemented command is sent to uvmm
   * via the monitor console interface, possibly with additional arguments.
   */
  virtual void exec(FILE *f, char const *args) = 0;

  /**
   * Register command.
   *
   * \param name  The command name under which this handler will be accessible
   *              via the monitor console interface.
   *
   * This method registers this handler with the monitor console interface and
   * thus makes it available as an additional top level command.
   */
  void register_toplevel(char const *name);

  /**
   * Destructor.
   *
   * Upon destruction of this object, the handler will be automatically
   * unregistered from the monitor console interface.
   */
  virtual ~Cmd();

protected:
  Cmd() = default;
};

#ifdef CONFIG_MONITOR
/**
 * Enable the monitor console.
 *
 * \param registry  Object registry with which to register the monitor console
 *                  capability through which the monitor console interface can
 *                  be accessed. This capability is always registered under the
 *                  name `"mon"`.
 *
 * Note that this function will have no effect if monitor console support has
 * not been enabled during compilation, i.e. if `Enabled` is `false`. This
 * function should be called unconditionally during startup of uvmm such that
 * the availability of the monitor console only depends on the presence of the
 * `"mon"` capability.
 */
void enable_cmd_control(L4::Registry_iface *registry);

/**
 * Check if the monitor console has been enabled.
 *
 * \return  `true` if monitor console support has been enabled during
 *          compilation, a valid `"mon"` capability has been provided and
 *          `enable_cmd_control` has been invoked previously.
 */
bool cmd_control_enabled();
#else
inline void enable_cmd_control(L4::Registry_iface *registry)
{ (void)registry; }

inline bool cmd_control_enabled()
{ return false; }
#endif

}
