/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "debug.h"

namespace Vmm {

/**
 * A simple console output buffer to be used with early print
 * implementations via hypcall.
 */
class Guest_print_buffer
{
public:

  Guest_print_buffer()
  : _early_print_pos(0)
  {
    _early_print_buf[255] = '\0';
  }

  void print_char(char c)
  {
    if (!(c == '\n' || c == '\0'))
      _early_print_buf[_early_print_pos++] = c;

    if (_early_print_pos >= 255 || c == '\n' || c == '\0')
      {
        _early_print_buf[_early_print_pos] = '\0';
        Dbg(Dbg::Guest, Dbg::Warn, "GUEST").printf("%s\n", _early_print_buf);
        _early_print_pos = 0;
      }
  }

private:
  char _early_print_buf[256];
  unsigned _early_print_pos;
};

} // namespace
