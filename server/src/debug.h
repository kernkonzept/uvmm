/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/util/debug>

struct Err : L4Re::Util::Err
{
  Err(Level l = Fatal) : L4Re::Util::Err(l, "VMM") {}
};

struct Dbg : L4Re::Util::Dbg
{
  /// Verbosity level per component.
  enum Verbosity : unsigned long
  {
    Quiet = 0,
    Warn = 1,
    Info = 2,
    Trace = 4,
  };

  enum
  {
    Verbosity_shift = 3, /// Bits per component for verbosity
    Verbosity_mask = (1UL << Verbosity_shift) - 1
  };

  /**
   * Different components for which the verbosity can be set independently.
   */
  enum Component
  {
    Guest = 0,
    Core,
    Cpu,
    Mmio,
    Irq,
    Dev,
    Pm,
    Vbus_event,
    Max_component
  };

  static_assert(Max_component * Verbosity_shift <= sizeof(level) * 8,
                "Too many components for level mask");

  /**
   * Set the verbosity for all components to the given levels.
   *
   * \param mask  Mask of verbosity levels.
   */
  static void set_verbosity(unsigned mask)
  {
    for (unsigned i = 0; i < Max_component; ++i)
      set_verbosity(i, mask);
  }

  /**
   * Set the verbosity of a single component to the given level.
   *
   * \param c     Component for which to set verbosity.
   * \param mask  Mask of verbosity levels.
   */
  static void set_verbosity(unsigned c, unsigned mask)
  {
    level &= ~(Verbosity_mask << (Verbosity_shift * c));
    level |= (mask & Verbosity_mask) << (Verbosity_shift * c);
  }

  Dbg(Component c = Core, Verbosity v = Warn, char const *subsys = "")
  : L4Re::Util::Dbg(v << (Verbosity_shift * c), "VMM", subsys)
  {}
};
