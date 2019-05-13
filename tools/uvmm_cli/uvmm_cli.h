/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

/**
 * \file
 * Uvmm CLI server protocol constants.
 *
 * The CLI server implements a readline interface and is able to send commands
 * and completion requests to uvmm and in return receive and display command
 * output and completions. This way no readline code has to be included inside
 * uvmm itself.
 *
 * The protocol by which the CLI server and uvmm exchange data is currently
 * implemented as follows:
 *
 * Once a (non-empty) line is entered on the CLI server, the CLI server
 * triggers an IRQ that causes a handler inside uvmm to read the complete line
 * via the Vcon protocol which is implemented by an object that the CLI server
 * exports under the name 'mon'. Lines read by uvmm are already automatically
 * stripped of leading and trailing whitespace with all remaining spaces
 * 'compressed' such that any adjacent spaces are combined into a single one.
 * Uvmm then tries to interpret these lines as commands by using the first word
 * in each line to look up an object implementing the `Monitor::Cmd` interface
 * and passing the rest of the line as arguments to that objects `exec` method.
 *
 * Output resulting from successful or failed command execution is sent back to
 * the CLI server which is blocked for further readline input until the output
 * has arrived completely. Because command output can be comprised of more than
 * one line of text, uvmm has to send a token signifying the end of a commands
 * output on every transmission. Currently this is the EOT (0x04) ASCII
 * character followed by a single newline ('\n'). If this token is not sent,
 * the CLI server will block indefinitely.
 *
 * Command completion works similarly to command transmission. A command
 * completion request is made by providing a line ending in "\t\n" to uvmm.
 * This happens when the user of the CLI server enters the TAB key, the line
 * transmitted is then the currently displayed line until the current cursor
 * position (plus "\t\n"). Uvmm will then try to find possible completions for
 * this partial command, delegating the completion to components implementing
 * the Monitor::Cmd interface if the word to be completed occurs after the
 * first one in the line. The completions are sent back to the CLI server the
 * same way command output is, all possible completions are transmitted in one
 * line, separated by '\n' characters, as before this line ends with EOT +
 * '\n'. The list of completions should be be comprised of completions for the
 * last word in the partial command line, not the whole line itself.
 */

namespace Uvmm_cli {

enum : char {
  /**
   * Delimiting token that must be included at the end of every commands
   * output.
   */
  PROTO_EOT = 0x04,
  /**
   * Token used to indicate a completion request.
   */
  PROTO_COMPL_REQ = '\t',
  /**
   * Token used to separate possible completions sent back to the CLI server
   * by uvmm.
   */
  PROTO_COMPL_SEP = '\n'
};

enum : l4_umword_t {
  /**
   * The CLI server server sets this local vcon attribute so that uvmm can
   * detect that a readline interface is available and turn off its own console
   * prompt.
   */
  ENABLED = 000020
};

}
