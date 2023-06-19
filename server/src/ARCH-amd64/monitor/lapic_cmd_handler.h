/*
 * Copyright (C) 2019-2020, 2023 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>
#include <cstring>

#include <l4/sys/l4int.h>

#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Lapic_cmd_handler {};

template<typename T>
class Lapic_cmd_handler<true, T> : public Cmd
{
  enum { Chunk_size = 4 };

  struct Apic_register
  {
    Apic_register(char const *name, unsigned msr, unsigned bytes = 4)
    : name(name), msr(msr), bytes(bytes)
    {}

    char const *name;
    unsigned msr;
    unsigned bytes;
  };

public:
  Lapic_cmd_handler()
  { register_toplevel("lapic"); }

  char const *help() const override
  { return "Local APIC registers"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n"
               "* 'lapic <i>': dump local APIC registers for a specific cpu\n"
               "* 'lapic all': dump local APIC registers for all cpus\n",
            help());
  }

  void exec(FILE *f, Arglist *args) override
  {
    if (*args == "all")
      {
        unsigned i = 0;
        while (lapic_check(i))
          {
            fprintf(f, "LAPIC %u\n", i);
            show_lapic(f, i);
            fprintf(f, "\n");
            ++i;
          }
      }
    else
      {
        unsigned lapic_no =
          args->pop<unsigned>("Failed to parse local APIC number.");

        if (!lapic_check(lapic_no))
          argument_error("No such CPU or no local APIC registers found");

        show_lapic(f, lapic_no);
      }
  }

  void show_lapic(FILE *f, unsigned lapic_no) const
  {
    static Apic_register registers[] = {
      { "Local APIC ID",                           0x802 },
      { "Local APIC Version",                      0x803 },
      { "Task Priority",                           0x808 },
      { "Process Priority",                        0x80a },
      { "Logical Destination",                     0x80d },
      { "Destination Format",                      0x80e },
      { "Spurious Vector",                         0x80f },
      { "In-Service",                              0x810, 32 },
      { "Trigger Mode",                            0x818, 32 },
      { "Interrupt Request",                       0x820, 32 },
      { "Error Status",                            0x828 },
      { "Corrected Machine Check Error Interrupt", 0x82f },
      { "Interrupt Command",                       0x830, 8 },
      { "LVT Timer",                               0x832 },
      { "LVT Thermal Sensor",                      0x833 },
      { "LVT Performance Monitoring Counters",     0x834 },
      { "LVT LINT0",                               0x835 },
      { "LVT LINT1",                               0x836 },
      { "LVT Error",                               0x837 },
      { "Initial Count",                           0x838 },
      { "Current Count",                           0x839 },
      { "TSC Deadline",                            0x6e0 }
    };

    fprintf(f, "|%-5s |%-5s |%-40s |%-18s |\n",
            "MSR", "Bytes", "Name", "Value");

    for (auto const &r : registers)
      {
        if (r.bytes <= 8)
          {
            print_row(f, lapic_no, r);
          }
        else
          {
            for (unsigned chunk = 0; chunk < r.bytes / Chunk_size; ++chunk)
              print_row(f, lapic_no, r, chunk);
          }
      }
    print_row(f, "Is NMI pending",
              static_cast<T const *>(this)->get(lapic_no)->is_nmi_pending());
  }

private:
  void print_row(FILE *f, char const *name, l4_uint64_t value) const
  {
    fprintf(f, "|0x%03x |%-5u ", 0, 0);
    fprintf(f, "|%-40s ", name);

    unsigned bytes = 4;
    fprintf(f,
            "|0x%0*llx%.*s ",
            bytes * 2,
            value,
            (8 - bytes) * 2,
            "        ");
    fprintf(f,"|\n");
  }

  void print_row(FILE *f, unsigned lapic_no, Apic_register const &r) const
  {
    print_location(f, r.msr, r.bytes);

    fprintf(f, "|%-40s ", r.name);

    print_value(f, lapic_no, r.msr, r.bytes);

    fprintf(f,"|\n");
  }

  void print_row(FILE *f,
                 unsigned lapic_no,
                 Apic_register const &r,
                 unsigned chunk) const
  {
    print_location(f, r.msr, Chunk_size);

    fprintf(f,
            "|[%3u:%3u] %-30s ",
            chunk * Chunk_size * 8,
            (chunk + 1) * Chunk_size * 8 - 1,
            r.name);

    print_value(f, lapic_no, r.msr + chunk, Chunk_size);

    fprintf(f,"|\n");
  }

  void print_location(FILE *f, unsigned msr, unsigned bytes) const
  { fprintf(f, "|0x%03x |%-5u ", msr, bytes); }

  void print_value(FILE *f,
                   unsigned lapic_no,
                   unsigned msr,
                   unsigned bytes) const
  {
    l4_uint64_t value;
    if (!lapic_read_msr(lapic_no, msr, &value))
      {
        fprintf(f, "Failed to read Local APIC register\n");
        return;
      }

    fprintf(f,
            "|0x%0*llx%.*s ",
            bytes * 2,
            value,
            (8 - bytes) * 2,
            "        ");
  }

  bool lapic_check(unsigned lapic_no) const
  { return static_cast<T const *>(this)->get(lapic_no) != nullptr; }

  bool lapic_read_msr(unsigned lapic_no, unsigned msr, l4_uint64_t *value) const
  {
    return lapic_check(lapic_no)
           && static_cast<T const *>(this)->get(lapic_no)->read_msr(msr, value);
  }
};

}
