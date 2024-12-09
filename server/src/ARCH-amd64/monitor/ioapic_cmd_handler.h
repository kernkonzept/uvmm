/*
 * Copyright (C) 2024 Kernkonzept GmbH.
 * Author(s): Timo Nicolai <timo.nicolai@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <cstdio>
#include <cstring>
#include <string>

#include <l4/sys/l4int.h>

#include "monitor/monitor.h"
#include "monitor/monitor_args.h"

namespace Monitor {

template<bool, typename T>
class Ioapic_cmd_handler {};

template<typename T>
class Ioapic_cmd_handler<true, T> : public Cmd
{
  enum Ioapic_regs
  {
    Id_reg = 0x0,
    Version_reg = 0x1,
    Arbitration_reg = 0x2,
    Redir_tbl_offset_reg = 0x10,
    Redir_tbl_last_reg = 0x3f,
  };

  struct Ioapic_reg
  {
    char const *name;
    unsigned addr;
    unsigned bytes;
  };

public:
  Ioapic_cmd_handler()
  { register_toplevel("ioapic"); }

  char const *help() const override
  { return "IO APIC registers"; }

  void usage(FILE *f) const override
  {
    fprintf(f, "%s\n", help());
  }

  void exec(FILE *f, Arglist * /*args*/) override
  {
    show_ioapic(f);
  }

  void show_ioapic(FILE *f) const
  {
    Ioapic_reg ioapic_regs[] =
      {
        {"IOAPIC ID", Id_reg, 4},
        {"IOAPIC Version", Version_reg, 4},
        {"IOAPIC Arbitration ID", Arbitration_reg, 4},
      };

    fprintf(f, "|%-5s |%-5s |%-30s |%-18s |\n",
            "Reg", "Bytes", "Name", "Value");

    for (auto const &reg : ioapic_regs)
      print_row(f, reg);

    print_redirection_table(f);
  }

private:
  void print_redirection_table(FILE *f) const
  {
    for (unsigned reg = Redir_tbl_offset_reg; reg < Redir_tbl_last_reg;
         reg += 2)
      print_redir_row(f, reg, "Redirection table ",
                      (reg - Redir_tbl_offset_reg) / 2);
  }

  void print_redir_row(FILE *f, unsigned addr, std::string name,
                       unsigned idx) const
  {
    unsigned bytes = 8;
    print_location(f, addr, bytes);

    name.append(std::to_string(idx));
    fprintf(f, "|%-30s ", name.c_str());

    l4_uint64_t lower = ioapic_read(addr);
    l4_uint64_t upper = ioapic_read(addr + 1);

    fprintf(f,
            "|0x%0*llx%.*s ",
            bytes * 2,
            (upper << 32) | (lower & 0xffff'ffffU),
            (8 - bytes) * 2,
            "        ");

    fprintf(f,"|\n");
  }

  void print_row(FILE *f, Ioapic_reg const &r) const
  {
    print_location(f, r.addr, r.bytes);

    fprintf(f, "|%-30s ", r.name);

    print_value(f, r.addr, r.bytes);

    fprintf(f,"|\n");
  }

  void print_location(FILE *f, unsigned reg, unsigned bytes) const
  { fprintf(f, "|0x%03x |%-5u ", reg, bytes); }

  void print_value(FILE *f, unsigned reg, unsigned bytes) const
  {
    l4_uint64_t value = ioapic_read(reg);
    if (value == -1ULL)
      {
        fprintf(f, "Failed to read IOAPIC register\n");
        return;
      }

    fprintf(f,
            "|0x%0*llx%.*s ",
            bytes * 2,
            value,
            (8 - bytes) * 2,
            "        ");
  }

  T const *ioapic() const
  { return static_cast<T const *>(this); }

  l4_uint64_t ioapic_read(unsigned reg) const
  { return ioapic()->read_reg(reg); }
};

}
