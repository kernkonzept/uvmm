/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/utcb.h>

#include <assert.h>

#include "debug.h"

namespace L4mad
{

enum Desc_type { Desc_mem, Desc_imm, Desc_reg, Desc_regbitmap };
enum Access_type { Write, Read };

struct Desc
{
  Desc_type dtype;
  l4_umword_t val;
  unsigned char shift;

  void set_mem(l4_umword_t v)
  { dtype = Desc_mem; val = v; shift = 0; }

  void set_reg(l4_umword_t v, unsigned char s = 0)
  { dtype = Desc_reg; val = v; shift = s; }

  void set_regbitmap(l4_umword_t bm)
  { dtype = Desc_regbitmap; val = bm; shift = 0; }

  void set_imm(l4_umword_t v)
  { dtype = Desc_imm; val = v; shift = 0; }
};

struct Op
{
  Access_type atype;
  unsigned char access_width;
  unsigned char insn_len;

  void set(Access_type t, unsigned char aw, unsigned char il)
  {
    atype        = t;
    access_width = aw;
    insn_len     = il;
  }
};

#if defined(ARCH_amd64)
enum { Num_registers = 16, };
#elif defined(ARCH_x86)
enum { Num_registers = 8, };
#endif

class Decoder
{
public:
  l4_addr_t l4mad_print_insn_info(l4_exc_regs_t *u, l4_addr_t pc);

  bool decode(l4_exc_regs_t *u, l4_addr_t pc, Op *op, Desc *tgt, Desc *src);

private:
  static Dbg trace() { return Dbg(Dbg::Core, Dbg::Trace); }

  char *desc_s(l4_exc_regs_t *u, char *buf, unsigned buflen, Desc *d,
               unsigned aw);
  void regname_bm_snprintf(l4_exc_regs_t *u, char *buf, unsigned buflen,
                           unsigned reglist);
  const char *regname(unsigned regnr, unsigned shift, unsigned aw);
  inline l4_umword_t regval_arch(l4_exc_regs_t *u, unsigned regnr);
  l4_umword_t regval(l4_exc_regs_t *u, unsigned regnr, unsigned shift,
                     unsigned aw);

  unsigned char getbyte(l4_umword_t a)
  {
    return *(unsigned char *)a; // check for validity
  }

  l4_umword_t readval(l4_addr_t a, char sz)
  {
    switch (sz)
      {
      case 1: return *(unsigned char *)a;
      case 2: return *(unsigned short *)a;
      case 4: return *(unsigned int *)a;
      case 8: return *(unsigned long long *)a;
      }
    // actually unreachable, so compile time assertion
    assert(0);
    return ~0UL;
  }

}; // class Decoder

} // namespace L4mad
