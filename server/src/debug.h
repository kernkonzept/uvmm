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
#include <l4/sys/err.h>

struct Err : L4Re::Util::Err
{
  Err(Level l = Fatal) : L4Re::Util::Err(l, "VMM") {}
};

class Dbg : public L4Re::Util::Dbg
{
public:
  /// Verbosity level per component.
  enum Verbosity : unsigned long
  {
    Quiet = 0,
    Warn = 1,
    Info = 2,
    Trace = 4,
  };

  /**
   * Different components for which the verbosity can be set independently.
   */
  enum Component
  {
    Core = 0,
    Cpu,
    Mmio,
    Irq,
    Dev,
    Pm,
    Vbus_event,
    Max_component
  };

#ifndef NDEBUG
  enum
  {
    Verbosity_shift = 3, /// Bits per component for verbosity
    Verbosity_mask = (1UL << Verbosity_shift) - 1
  };

  static_assert(Max_component * Verbosity_shift <= sizeof(level) * 8,
                "Too many components for level mask");


  /**
   * Get the current verbosity level for a single component.
   *
   * \param c         Component for which to query verbosity.
   * \param[out] str  Pointer to the name of the current verbosity level for the
   *                  given component (if the operation succeeded).
   *
   * \retval L4_EOK      Operation succeeded.
   * \retval -L4_EINVAL  Invalid component.
   */
  static int get_verbosity(unsigned c, char const **str);

  /**
   * Get the current verbosity level for a single component.
   *
   * \param c         Name of the component for which to query verbosity.
   * \param[out] str  Pointer to the name of the current verbosity level for the
   *                  given component (if the operation succeeded).
   *
   * \retval L4_EOK      Operation succeeded.
   * \retval -L4_EINVAL  Invalid component name.
   */
  static int get_verbosity(char const *c, char const **str);

  /**
   * Obtain an array of valid verbosity levels.
   *
   * \return  Pointer to array containing verbosity level strings, terminated by
   *          a null pointer.
   */
  static char const *const *valid_verbosity_levels();

  /**
   * Obtain an array of valid components for which the verbosity can be set.
   *
   * \return  Pointer to array containing component identifier strings,
   *          terminated by a null pointer.
   */
  static char const *const *valid_components();

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

  /**
   * Set debug level according to a verbosity string.
   *
   * The string may either set a global verbosity level:
   *   quiet, warn, info, trace
   *
   * Or it may set the verbosity level for a component:
   *
   *   <component>=<level>
   *
   * where component is one of: core, cpu, mmio, irq, dev, pm, vbus_event
   * and level the same as above.
   *
   * To change the verbosity of multiple components repeat
   * the verbosity switch.
   *
   * \retval L4_EOK      operation succeeded
   * \retval -L4_EINVAL  invalid verbosity string
   *
   * Example:
   *
   *  uvmm -D info -D irq=trace
   *
   *    Sets verbosity for all components to info except for
   *    IRQ handling which is set to trace.
   *
   *  uvmm -D trace -D dev=warn -D mmio=warn
   *
   *    Enables tracing for all components except devices
   *    and mmio.
   *
   */
  static int set_verbosity(char const *str);

#else
  static int get_verbosity(unsigned, char const **)
  { return -L4_EINVAL; }
  static int get_verbosity(char const *, char const **)
  { return -L4_EINVAL; }
  static void set_verbosity(unsigned, unsigned) {}
  static void set_verbosity(unsigned) {}
  static int set_verbosity(char const *)
  { return -L4_EINVAL; }

  Dbg(Component /* c */ = Core, Verbosity /* v */ = Warn ,
      char const * /* subsys */ = "")
  {}
#endif
};
