/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/cxx/bitfield>

#include "mem_access.h"

namespace Riscv {

namespace Op {

  enum
  {
    Lb  = 0x3,
    Lbu = 0x4003,
    Lh  = 0x1003,
    Lhu = 0x5003,
    Lw  = 0x2003,
    Lwu = 0x6003,
    Ld  = 0x3003,
    Sb  = 0x23,
    Sh  = 0x1023,
    Sw  = 0x2023,
    Sd  = 0x3023,
  };

  enum
  {
    Opcode_mask = 0x707f,
  };

  enum
  {
    C_lw   = 0x4000,
    C_ld   = 0x6000,
    C_lwsp = 0x4002,
    C_ldsp = 0x6002,
    C_sw   = 0xc000,
    C_sd   = 0xe000,
    C_swsp = 0xc002,
    C_sdsp = 0xe002,
  };

  enum
  {
    C_opcode_mask = 0xe003,
  };

}

namespace Inst {

  enum
  {
    Wfi = 0x10500073,
  };

}

namespace Reg {

  enum
  {
    Sp = 0x02,
  };

}


static bool is_compressed_inst(l4_uint32_t inst)
{
  // Instructions wider than 16 bits have the two least-significant bits set.
  return (inst & 0b11) != 0b11;
}

// Holds instructions transformed according to RISC-V privileged spec.
struct Instruction
{
  l4_uint32_t inst;
  // Generic fields
  CXX_BITFIELD_MEMBER(7, 11, rd, inst);
  CXX_BITFIELD_MEMBER(15, 19, rs1, inst);
  CXX_BITFIELD_MEMBER(20, 24, rs2, inst);

  Instruction(l4_uint32_t inst) : inst(inst) {}

  l4_uint32_t opcode()
  {
    // Transformed instructions are uncompressed instructions,
    // but use bit 1 to indicate that the raw instruction was compressed.
    return (inst | 0b10) & Op::Opcode_mask;
  }

  bool is_load()
  {
    switch(opcode())
    {
      case Op::Lb:
      case Op::Lbu:
      case Op::Lh:
      case Op::Lhu:
      case Op::Lw:
      case Op::Lwu:
      case Op::Ld:
        return true;
      default:
        return false;
    }
  }

  bool is_unsigned_load()
  {
    switch(opcode())
    {
      case Op::Lbu:
      case Op::Lhu:
      case Op::Lwu:
        return true;
      default:
        return false;
    }
  }

  bool is_store()
  {
    switch(opcode())
    {
      case Op::Sb:
      case Op::Sh:
      case Op::Sw:
      case Op::Sd:
        return true;
      default:
        return false;
    }
  }

  Vmm::Mem_access::Width load_store_width()
  {
    switch(opcode())
    {
      case Op::Lb:
      case Op::Lbu:
      case Op::Sb:
        return Vmm::Mem_access::Wd8;
      case Op::Lh:
      case Op::Lhu:
      case Op::Sh:
        return Vmm::Mem_access::Wd16;
      case Op::Lw:
      case Op::Lwu:
      case Op::Sw:
        return Vmm::Mem_access::Wd32;
      case Op::Ld:
      case Op::Sd:
        return Vmm::Mem_access::Wd64;
      default:
        return Vmm::Mem_access::Wd32;
    }
  }

  bool is_wfi()
  {
    return inst == Inst::Wfi;
  }

  bool is_compressed()
  {
    return is_compressed_inst(inst);
  }

  l4_uint32_t inst_size()
  {
    return is_compressed() ? 2 : 4;
  }
};

// Compressed instruction.
struct C_instruction
{
  l4_uint32_t inst;

  // CL+CS format
  CXX_BITFIELD_MEMBER_RO(7, 9, rs1_c, inst);
  // CL format
  CXX_BITFIELD_MEMBER_RO(2, 4, rd_c, inst);
  // CS format
  CXX_BITFIELD_MEMBER_RO(2, 4, rs2_c, inst);
  // CI format
  CXX_BITFIELD_MEMBER_RO(7, 11, rd, inst);
  // CSS format
  CXX_BITFIELD_MEMBER_RO(2, 6, rs2, inst);

  C_instruction(l4_uint32_t inst) : inst(inst) {}

  Instruction transformed()
  {
    Instruction tinst(0);
    switch (inst & Op::C_opcode_mask)
    {
      case Op::C_lw:
        tinst = Op::Lw;
        tinst.rs1() = map_reg(rs1_c());
        tinst.rd() = map_reg(rd_c());
        break;
      case Op::C_ld:
        tinst = Op::Ld;
        tinst.rs1() = map_reg(rs1_c());
        tinst.rd() = map_reg(rd_c());
        break;
      case Op::C_lwsp:
        // C.LWSP is only valid when rd=x0
        if (rd() != 0)
          {
            tinst = Op::Lw;
            tinst.rs1() = Reg::Sp;
            tinst.rd() = rd();
          }
        break;
      case Op::C_ldsp:
        // C.LDSP is only valid when rd=x0
        if (rd() != 0)
          {
            tinst = Op::Ld;
            tinst.rs1() = Reg::Sp;
            tinst.rd() = rd();
          }
        break;
      case Op::C_sw:
        tinst = Op::Sw;
        tinst.rs1() = map_reg(rs1_c());
        tinst.rs2() = map_reg(rs2_c());
        break;
      case Op::C_sd:
        tinst = Op::Sd;
        tinst.rs1() = map_reg(rs1_c());
        tinst.rs2() = map_reg(rs2_c());
        break;
      case Op::C_swsp:
        tinst = Op::Sw;
        tinst.rs1() = Reg::Sp;
        tinst.rs2() = rs2();
        break;
      case Op::C_sdsp:
        tinst = Op::Sd;
        tinst.rs1() = Reg::Sp;
        tinst.rs2() = rs2();
        break;
    }

    // Replace bit 1 with a 0.
    return tinst.inst & ~static_cast<l4_uint32_t>(0b10);
  }

  static l4_uint32_t map_reg(l4_uint32_t reg_c)
  {
    assert(reg_c <= 0b111);
    return reg_c + 8;
  }
};

}
