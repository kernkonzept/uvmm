/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Christian Pötzsch <christian.poetzsch@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/sys/thread.h>
#include <l4/re/elf_aux.h>
#include "guest.h"

L4RE_ELF_AUX_ELEM_T(l4re_elf_aux_mword_t, __ex_regs_flags,
                    L4RE_ELF_AUX_T_EX_REGS_FLAGS,
                    L4_THREAD_EX_REGS_ARM64_SET_EL_EL1);

asm (
  ".global __l4_sys_syscall\n"
  ".type __l4_sys_syscall, @function\n"
  "__l4_sys_syscall:\n"
  "   hvc #0\n"
  "   ret\n"
);

namespace {

bool
has_aarch32()
{
  l4_uint64_t aa64pfr0;
  asm ("mrs %0, ID_AA64PFR0_EL1" : "=r"(aa64pfr0));
  return (aa64pfr0 & 0x0f) == 2;
}

}

namespace Vmm {

void
Guest::add_sys_reg_aarch64(unsigned op0, unsigned op1,
                           unsigned crn, unsigned crm,
                           unsigned op2,
                           cxx::Ref_ptr<Vmm::Arm::Sys_reg> const &r)
{
  _sys_regs[Vmm::Arm::Sys_reg::Key::sr(op0, op1, crn, crm, op2)] = r;
}

#define CP(coproc,opc1,CRn,CRm,opc2) "S" #coproc "_" #opc1 "_C" #CRn "_C" #CRm "_" #opc2

void
Guest::subarch_init()
{
  using namespace Arm;

  // Registers sorted according to encoding. See chapter
  //
  //   D22.3.1 Instructions for accessing non-debug System registers
  //
  // in Arm Architecture Reference Manual ARM DDI 0487K.a.

  if (has_aarch32())
    {
      // ID_PFR0_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,0) : "=r"(regval));
        return regval;
      }));

      // ID_PFR1_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,1) : "=r"(regval));
        return regval;
      }));

      // ID_DFR0_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 2, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,2) : "=r"(regval));
        return regval;
      }));

      // ID_AFR0_EL1 skipped intentionally

      // ID_MMFR0_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 4, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,4) : "=r"(regval));
        return regval;
      }));

      // ID_MMFR1_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 5, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,5) : "=r"(regval));
        return regval;
      }));

      // ID_MMFR2_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 6, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,6) : "=r"(regval));
        return regval;
      }));

      // ID_MMFR3_EL1
      add_sys_reg_aarch64(3, 0, 0, 1, 7, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,1,7) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR0_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,0) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR1_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,1) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR2_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 2, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,2) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR3_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 3, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,3) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR4_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 4, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,4) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR5_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 5, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,5) : "=r"(regval));
        return regval;
      }));

      // ID_MMFR4_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 6, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,6) : "=r"(regval));
        return regval;
      }));

      // ID_ISAR6_EL1
      add_sys_reg_aarch64(3, 0, 0, 2, 7, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,2,7) : "=r"(regval));
        return regval;
      }));

      // ID_MVFR0_EL1
      add_sys_reg_aarch64(3, 0, 0, 3, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,3,0) : "=r"(regval));
        return regval;
      }));

      // ID_MVFR1_EL1
      add_sys_reg_aarch64(3, 0, 0, 3, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,3,1) : "=r"(regval));
        return regval;
      }));

      // ID_MVFR2_EL1
      add_sys_reg_aarch64(3, 0, 0, 3, 2, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,3,2) : "=r"(regval));
        return regval;
      }));

      // ID_PFR2_EL1
      add_sys_reg_aarch64(3, 0, 0, 3, 4, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,3,4) : "=r"(regval));
        return regval;
      }));

      // ID_DFR1_EL1
      add_sys_reg_aarch64(3, 0, 0, 3, 5, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,3,5) : "=r"(regval));
        return regval;
      }));

      // ID_MMFR5_EL1
      add_sys_reg_aarch64(3, 0, 0, 3, 6, cxx::make_ref_obj<Sys_reg_feat>([](){
        l4_uint64_t regval;
        asm volatile("mrs %0, " CP(3,0,0,3,6) : "=r"(regval));
        return regval;
      }));
    }

  // ID_AA64PFR0_EL1
  add_sys_reg_aarch64(3, 0, 0, 4, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,4,0) : "=r"(regval));

    regval &= ~(15ULL << 32); // Mask SVE feature

    return regval;
  }));

  // ID_AA64PFR1_EL1
  add_sys_reg_aarch64(3, 0, 0, 4, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,4,1) : "=r"(regval));
    return regval;
  }));

  // ID_AA64PFR2_EL1
  add_sys_reg_aarch64(3, 0, 0, 4, 2, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,4,2) : "=r"(regval));
    return regval;
  }));

  // ID_AA64ZFR0_EL1
  add_sys_reg_aarch64(3, 0, 0, 4, 4, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,4,4) : "=r"(regval));
    return regval;
  }));

  // ID_AA64SMFR0_EL1
  add_sys_reg_aarch64(3, 0, 0, 4, 5, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,4,5) : "=r"(regval));
    return regval;
  }));

  // ID_AA64DFR0_EL1
  add_sys_reg_aarch64(3, 0, 0, 5, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,5,0) : "=r"(regval));
    return regval;
  }));

  // ID_AA64DFR1_EL1
  add_sys_reg_aarch64(3, 0, 0, 5, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,5,1) : "=r"(regval));
    return regval;
  }));

  // ID_AA64AFR0_EL1 skipped intentionally
  // ID_AA64AFR1_EL1 skipped intentionally

  // ID_AA64ISAR0_EL1
  add_sys_reg_aarch64(3, 0, 0, 6, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,6,0) : "=r"(regval));
    return regval;
  }));

  // ID_AA64ISAR1_EL1
  add_sys_reg_aarch64(3, 0, 0, 6, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,6,1) : "=r"(regval));

    regval &= ~(15ULL << 44); // Mask BF16 (FEAT_SVE)
    regval &= ~(15ULL << 28); // Mask GPI (FEAT_PAuth)
    regval &= ~(15ULL << 24); // Mask GPA (FEAT_PAuth)
    regval &= ~(15ULL << 8);  // Mask API (FEAT_PAuth)
    regval &= ~(15ULL << 4);  // Mask APA (FEAT_PAuth)

    return regval;
  }));

  // ID_AA64ISAR2_EL1
  add_sys_reg_aarch64(3, 0, 0, 6, 2, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,6,2) : "=r"(regval));

    regval &= ~(15ULL << 12); // Disable APA3 (FEAT_PAuth)
    regval &= ~(15ULL << 8);  // Disable GPA3 (FEAT_PAuth)

    return regval;
  }));

  // ID_AA64MMFR0_EL1
  add_sys_reg_aarch64(3, 0, 0, 7, 0, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,7,0) : "=r"(regval));
    return regval;
  }));

  // ID_AA64MMFR1_EL1
  add_sys_reg_aarch64(3, 0, 0, 7, 1, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,7,1) : "=r"(regval));
    return regval;
  }));

  // ID_AA64MMFR2_EL1
  add_sys_reg_aarch64(3, 0, 0, 7, 2, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,7,2) : "=r"(regval));
    return regval;
  }));

  // ID_AA64MMFR3_EL1
  add_sys_reg_aarch64(3, 0, 0, 7, 3, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,7,3) : "=r"(regval));
    return regval;
  }));

  // ID_AA64MMFR4_EL1
  add_sys_reg_aarch64(3, 0, 0, 7, 4, cxx::make_ref_obj<Sys_reg_feat>([](){
    l4_uint64_t regval;
    asm volatile("mrs %0, " CP(3,0,0,7,4) : "=r"(regval));
    return regval;
  }));
}

}
