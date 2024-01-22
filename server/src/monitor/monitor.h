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
#include <l4/bid_config.h>
#include "monitor/monitor_args.h"

namespace Vmm {
  class Vm;
}

namespace Monitor {

/// Monitor console state indicator
enum : bool {
  /// `True` if monitor console support has been enabled during compilation
#ifdef CONFIG_UVMM_MONITOR
  Enabled = true,
  /// `True` if guest debugger support has been enabled during compilation
  #if defined(CONFIG_BUILD_ARCH_amd64) && !defined(CONFIG_RELEASE_MODE)
    Guest_debugger_support = true
  #else
    Guest_debugger_support = false
  #endif
#else
  Enabled = false,
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
   * Display command usage message.
   *
   * \return  Stream to which to print usage message.
   *
   * \note  The `help <cmd>` command uses this function.
   */
  virtual void usage(FILE *f) const
  { fprintf(f, "%s\n", help()); }

  /**
   * Complete partial arguments.
   *
   * \param f          Stream to which completions are to be written.
   * \param compl_req  Command line to be completed.
   *
   * This method should examine whether there exist one or several suitable
   * completions for the partial arguments to the command implemented by this
   * monitor passed via `args`. If so, these completions should be written to
   * `f` in arbitrary order, separated by newlines (with an optional trailing
   * newline).  Otherwise this method should do nothing. When `args` is an
   * empty string, all possible subcommands should be output this way.
   */
  virtual void complete(FILE * /* f */,
                        Completion_request * /* compl_req */) const
  {}

  /**
   * Invoke command.
   *
   * \param f     Stream to which command output (both regular output and
   *              errors) should be written. The command output should always
   *              end with a final newline, unless no output is produced to
   *              begin with.
   *
   * \param args  Arguments passed to the command.
   *
   * This method is called when the implemented command is sent to uvmm
   * via the monitor console interface, possibly with additional arguments.
   */
  virtual void exec(FILE *f, Arglist *args) = 0;

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
   * Unregister command.
   *
   * Note that this is automatically called during destruction.
   */
  void unregister_toplevel();

  /**
   * Destructor.
   *
   * Upon destruction of this object, the handler will be automatically
   * unregistered from the monitor console interface.
   */
  virtual ~Cmd();
};

#ifdef CONFIG_UVMM_MONITOR
/**
 * Enable the monitor console.
 *
 * \param vm  Pointer to virtual machine object.
 *
 * This will make the monitor console interface available to other servers via
 * a capability registered under the name `"mon"`.
 *
 * Note that this function will have no effect if monitor console support has
 * not been enabled during compilation, i.e. if `Enabled` is `false`. This
 * function should be called unconditionally during startup of uvmm such that
 * the availability of the monitor console only depends on the presence of the
 * `"mon"` capability.
 */
void enable_cmd_control(Vmm::Vm *vm);

/**
 * Check if the monitor console has been enabled.
 *
 * \return  `true` if monitor console support has been enabled during
 *          compilation, a valid `"mon"` capability has been provided and
 *          `enable_cmd_control` has been invoked previously.
 */
bool cmd_control_enabled();
#else
inline void enable_cmd_control(Vmm::Vm *)
{}

inline bool cmd_control_enabled()
{ return false; }
#endif

}
