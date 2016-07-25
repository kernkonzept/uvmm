/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/cxx/bitfield>

namespace Mips {

namespace Op {

enum Opcode
{
  Special = 0, Regimm, J, Jal, Beq, Bne, Blez, Bgtz,
  Pop10 = 8, Addiu, Slti, Sltiu, Andi, Ori, Xori, Lui,
  Cop0 = 16, Cop1, Cop2, Cop1x, Beql, Bnel, Blezl, Bgtzl,
  Pop30 = 24, Special2 = 28, Jalx, Msa, Special3,
  Lb = 32, Lh, Lwlw, Lw, Lbu, Lhu, Lwr,
  Sb = 40, Sh, Swl, Sw, Swr = 46, Cache,
  Ll = 48, Lwc1, Lwc2, Pref, Ldc1 = 53, Pop66, Ld,
  Sc = 56, Swc1, Swc2, Pcrel, Sdc1 = 61, Pop76, Sd
};

enum Cop0_rs
{
  Cop0_mfc0 = 0, Cop0_mfh = 2, Cop0_mtc0 = 4, Cop0_mth = 6,
  Cop0_hypcall = 0x28,
};

enum Special
{
  Sp_jr = 8, Sp_jalr = 9
};

enum Regimm
{
  Bltz = 0, Bgez, Bltzl, Bgezl,
  Tgei = 8, Tgeiu, Tlti, Tltiu, Teqi,
  Nal =16, Bal, Bltzall, Bgezall
};

}

struct Instruction
{
  l4_uint32_t raw;
  // generic fields
  CXX_BITFIELD_MEMBER_RO(26, 31, opcode, raw);
  CXX_BITFIELD_MEMBER_RO(21, 25, rs, raw);
  CXX_BITFIELD_MEMBER_RO(16, 20, rt, raw);
  CXX_BITFIELD_MEMBER_RO( 0, 15, imm, raw);
  CXX_BITFIELD_MEMBER_RO( 0,  5, func, raw);
  CXX_BITFIELD_MEMBER_RO( 6, 10, sa, raw);
  CXX_BITFIELD_MEMBER_RO(11, 15, rd, raw);
  // HYPCALL fields
  CXX_BITFIELD_MEMBER_RO(11, 20, hypcall_code, raw);
  // opcode for load/store instructions
  // Note that not all combinations are valid.
  CXX_BITFIELD_MEMBER_RO(31, 31, opcode_mem, raw);
  CXX_BITFIELD_MEMBER_RO(30, 30, op_mem_atomic, raw);
  CXX_BITFIELD_MEMBER_RO(29, 29, op_mem_store, raw);
  CXX_BITFIELD_MEMBER_RO(28, 28, op_mem_unsigned, raw);
  CXX_BITFIELD_MEMBER_RO(26, 27, op_mem_width, raw);
  // for Cop0
  CXX_BITFIELD_MEMBER_RO(25, 25, cop0_co, raw);
  // for J/JAL
  CXX_BITFIELD_MEMBER_RO( 0, 25, instr_index, raw);

  Instruction(l4_uint32_t inst) : raw(inst) {}

  bool is_mfc0() const
  { return opcode() == Op::Cop0 && rs() == Op::Cop0_mfc0; }

  bool is_mtc0() const
  { return opcode() == Op::Cop0 && rs() == Op::Cop0_mtc0; }

  bool is_hypcall() const
  { return opcode() == Op::Cop0 && func() == Op::Cop0_hypcall; }

  bool is_wait() const
  { return opcode() == Op::Cop0 && cop0_co() && func() == 0x20 ; }

  bool is_simple_load_store() const
  {
    return opcode_mem() && !op_mem_atomic()
           && op_mem_width() != 2
           && !(op_mem_unsigned() &&
                (op_mem_store() || op_mem_width() == 4));
  }

  int branch_offset() const
  { return ((int) ((l4_int16_t) imm())) << 2; }
};

} // namespace
