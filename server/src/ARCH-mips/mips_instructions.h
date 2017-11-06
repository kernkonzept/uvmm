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
  Cop0_mfc0 = 0, Cop0_dmf = 1, Cop0_mfh = 2, Cop0_mtc0 = 4, Cop0_dmt,
  Cop0_mth = 6, Cop0_hypcall = 0x28,
};

enum Special
{
  Sp_jr = 8, Sp_jalr = 9
};

enum Special3
{
  Sp3_cachee = 0x1b,
  Sp3_cache = 0x25
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
  // for FP ops
  CXX_BITFIELD_MEMBER_RO(28, 28, op_fp_dc1, raw);
  // for cache ops
  CXX_BITFIELD_MEMBER_RO(18, 20, cache_optype, raw);

  Instruction(l4_uint32_t inst) : raw(inst) {}

  bool is_mfc0() const
  {
    return opcode() == Op::Cop0
             && (rs() == Op::Cop0_mfc0 || rs() == Op::Cop0_dmf);
  }

  bool is_mtc0() const
  {
    return opcode() == Op::Cop0
             && (rs() == Op::Cop0_mtc0 || rs() == Op::Cop0_dmt);
  }

  bool is_hypcall() const
  { return opcode() == Op::Cop0 && func() == Op::Cop0_hypcall; }

  bool is_wait() const
  { return opcode() == Op::Cop0 && cop0_co() && func() == 0x20 ; }

  bool is_cache_op() const
  {
    return opcode() == Op::Cache
           || (sizeof(l4_umword_t) == 8 && opcode() == Op::Special3
               && (func() == Op::Sp3_cache || func() == Op::Sp3_cachee));
  }

  bool is_simple_load_store() const
  {
    return (opcode_mem() && !op_mem_atomic()
            && op_mem_width() != 2
            && !(op_mem_unsigned() && op_mem_store()))
           || ((opcode() & 0x37) == 0x37);
  }

  bool is_fp_load_store() const
  {
    return opcode() == Op::Lwc1 || opcode() == Op::Sdc1
           || opcode() == Op::Ldc1 || opcode() == Op::Sdc1;
  }

  /**
   * Return width of a load/store operation.
   *
   * \pre The instruction is a load/store operation.
   *
   * \retval 0  Byte width (8bit).
   * \retval 1  Half-word width (16bit).
   * \retval 2  Word width (32bit).
   * \retval 3  Double-word width (64bit).
   */
  char load_store_width() const
  {
    switch (opcode())
      {
      case Op::Lb:
      case Op::Lbu:
      case Op::Sb:
        return 0;
      case Op::Lh:
      case Op::Lhu:
      case Op::Sh:
        return 1;
      case Op::Ld:
      case Op::Sd:
      case Op::Ldc1:
      case Op::Sdc1:
        return 3;
      default:
        return 2;
      }
  }

  int branch_offset() const
  { return ((int) ((l4_int16_t) imm())) << 2; }
};

} // namespace
