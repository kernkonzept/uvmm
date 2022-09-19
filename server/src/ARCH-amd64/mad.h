/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Adam Lackorzynski <adam@l4re.org>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/utcb.h>

#include <assert.h>

#include "debug.h"
#include "mem_access.h"

namespace L4mad
{

enum Desc_type { Desc_mem, Desc_imm, Desc_reg, Desc_regbitmap };
enum Access_type { Write, Read };

/// Width in bytes.
using Width = Vmm::Mem_access::Width;

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
  Width access_width;
  unsigned char insn_len;

  void set(Access_type t, Width aw, unsigned char il)
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

struct Modrm;
struct Instruction;

class Decoder
{
public:
  /**
   * Create decoder for the given execution state.
   *
   * \param regs          General-purpose registers
   * \param ip            Instruction pointer as guest virtual address (required
   *                      for RIP-relative addressing)
   * \param inst_buf      Buffer containing instruction bytes
   * \param inst_buf_len  Length of instruction byte buffer
   */
  Decoder(l4_exc_regs_t const *regs, l4_addr_t ip,
          unsigned char const *inst_buf, unsigned inst_buf_len);

  enum { Max_instruction_len = 15 };

  enum class Result
  {
    Success,
    Unsupported,
    Invalid,
  };

  /**
   * Decode instruction as a read or write operation.
   *
   * \param[out] op   Operation
   * \param[out] tgt  Target operand description
   * \param[out] src  Source operation description
   *
   * \retval Result::Success     Instruction was decoded successfully.
   * \retval Result::Unsupported Instruction decoding failed, because an
   *                             unsupported instruction was encountered.
   * \retval Result::Invalid     Instruction decoding failed, because an invalid
   *                             or incomplete instruction was encountered, for
   *                             example if the the instruction spans more bytes
   *                             than available in the decoders instruction
   *                             buffer.
   *
   * \note The decoder assumes that the CPU is executing in long 64-bit mode or
   *       long compatibility / protected mode in a 32-bit code segment (i.e.
   *       CS.d==1). Otherwise incorrect operand and address widths are
   *       calculated.
   */
  Result decode(Op *op, Desc *tgt, Desc *src);

  /**
   * Print textual representation of a successfully decoded instruction.
   */
  void print_insn_info(Op const &op, Desc const &tgt, Desc const &src) const;

private:
  static Dbg trace() { return Dbg(Dbg::Core, Dbg::Trace, "Mad"); }
  static Dbg warn() { return Dbg(Dbg::Core, Dbg::Warn, "Mad"); }

  Result decode_unsafe(Op *op, Desc *tgt, Desc *src);
  void decode_legacy_prefixes(Instruction &inst);
  void decode_rex_prefix(Instruction &inst);
  bool decode_modrm(Instruction &inst, unsigned char *opcode_ext = nullptr);
  l4_umword_t decode_sib(Instruction &inst, Modrm const &modrm);
  void decode_imm(Instruction &inst);
  void decode_imm_moffs(Instruction &inst);

  char *desc_s(char *buf, unsigned buflen, Desc const &d, Width aw) const;
  void regname_bm_snprintf(char *buf, unsigned buflen, unsigned reglist) const;
  char const *regname(unsigned regnr, unsigned shift, Width aw) const;
  l4_umword_t regval_arch(unsigned regnr) const;
  l4_umword_t regval(unsigned regnr, unsigned shift, Width aw) const;

  Width addr_width(Instruction const &inst) const;

  l4_umword_t peek_inst_bytes(Instruction const &inst, Width sz) const;
  l4_umword_t read_inst_bytes(Instruction &inst, Width sz) const;

  void reg_from_op_reg(Desc *desc, Instruction const &inst) const;
  void imm_from_op_imm(Desc *desc, Instruction const &inst) const;
  void mem_from_op_imm(Desc *desc, Instruction const &inst) const;
  void mem_from_op_addr(Desc *desc, Instruction const &inst) const;

  l4_exc_regs_t const *const _regs;
  l4_addr_t const _ip;
  unsigned char const *const _inst_buf;
  unsigned const _inst_buf_len;
  bool const _long_mode_64;
}; // class Decoder

} // namespace L4mad
