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
#define ADD_FEAT_REG(coproc, opc1, CRn, CRm, opc2, ...) \
  add_sys_reg_aarch64(coproc, opc1, CRn, CRm, opc2, cxx::make_ref_obj<Sys_reg_feat>([](){ \
    l4_uint64_t regval; \
    asm volatile("mrs %0, " CP(coproc, opc1, CRn, CRm, opc2) : "=r"(regval)); \
    return regval & (__VA_ARGS__); \
  }))


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
      ADD_FEAT_REG(3, 0, 0, 1, 0,
                     (  0UL << 28)  // Mask RAS
                   | (0xfUL << 24)  // DIT
                   | (  0UL << 20)  // Mask AMU
                   | (0xfUL << 16)  // CSV2
                   | (0xfUL << 12)  // State3 (T32EE)
                   | (0xfUL <<  8)  // State2 (Jazelle)
                   | (0xfUL <<  4)  // State1 (T32)
                   | (0xfUL <<  0)  // State0 (A32)
      );

      // ID_PFR1_EL1
      ADD_FEAT_REG(3, 0, 0, 1, 1,
                     (0xfUL << 28)  // GIC
                   | (0xfUL << 24)  // Virt_frac
                   | (0xfUL << 20)  // Sec_frac
                   | (0xfUL << 16)  // GenTimer
                   | (0xfUL << 12)  // Virtualization
                   | (0xfUL <<  8)  // MProgMod
                   | (0xfUL <<  4)  // Security
                   | (0xfUL <<  0)  // ProgMod
      );

      // ID_DFR0_EL1
      ADD_FEAT_REG(3, 0, 0, 1, 2,
                     (  0UL << 28)  // Mask TraceFilt
                   | (  0UL << 24)  // Mask PerfMon
                   | (  0UL << 20)  // Mask MProfDbg
                   | (  0UL << 16)  // Mask MMapTrc
                   | (  0UL << 12)  // Mask CopTrc
                   | (  0UL <<  8)  // Mask MMapDbg
                   | (  0UL <<  4)  // Mask CopSDbg
                   | (0xfUL <<  0)  // CopDbg
      );

      // ID_AFR0_EL1 skipped intentionally

      // ID_MMFR0_EL1
      ADD_FEAT_REG(3, 0, 0, 1, 4,
                     (0xfUL << 28)  // InnerShr
                   | (0xfUL << 24)  // FCSE
                   | (0xfUL << 20)  // AuxReg
                   | (0xfUL << 16)  // TCM
                   | (0xfUL << 12)  // ShareLvl
                   | (0xfUL <<  8)  // OuterShr
                   | (0xfUL <<  4)  // PMSA
                   | (0xfUL <<  0)  // VMSA
      );

      // ID_MMFR1_EL1
      ADD_FEAT_REG(3, 0, 0, 1, 5,
                     (0xfUL << 28)  // BPred
                   | (0xfUL << 24)  // L1TstCln
                   | (0xfUL << 20)  // L1Uni
                   | (0xfUL << 16)  // L1Hvd
                   | (0xfUL << 12)  // L1UniSW
                   | (0xfUL <<  8)  // L1HvdSW
                   | (0xfUL <<  4)  // L1UniVA
                   | (0xfUL <<  0)  // L1HvdVA
      );

      // ID_MMFR2_EL1
      ADD_FEAT_REG(3, 0, 0, 1, 6,
                     (0xfUL << 28)  // HWAccFlg
                   | (0xfUL << 24)  // WFIStall
                   | (0xfUL << 20)  // MemBarr
                   | (0xfUL << 16)  // UniTLB
                   | (0xfUL << 12)  // HvdTLB
                   | (0xfUL <<  8)  // L1HvdRng
                   | (0xfUL <<  4)  // L1HvdBG
                   | (0xfUL <<  0)  // L1HvdFG
      );

      // ID_MMFR3_EL1
      ADD_FEAT_REG(3, 0, 0, 1, 7,
                     (0xfUL << 28)  // Supersec
                   | (0xfUL << 24)  // CMemSz
                   | (0xfUL << 20)  // CohWalk
                   | (0xfUL << 16)  // PAN
                   | (0xfUL << 12)  // MaintBcst
                   | (0xfUL <<  8)  // BPMaint
                   | (0xfUL <<  4)  // CMaintSW
                   | (0xfUL <<  0)  // CMaintVA
      );

      // ID_ISAR0_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 0,
                     (  0UL << 28)  // RES0
                   | (0xfUL << 24)  // Divide
                   | (0xfUL << 20)  // Debug
                   | (0xfUL << 16)  // Coproc
                   | (0xfUL << 12)  // CmpBranch
                   | (0xfUL <<  8)  // BitField
                   | (0xfUL <<  4)  // BitCount
                   | (0xfUL <<  0)  // Swap
      );

      // ID_ISAR1_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 1,
                     (0xfUL << 28)  // Jazelle
                   | (0xfUL << 24)  // Interwork
                   | (0xfUL << 20)  // Immediate
                   | (0xfUL << 16)  // IfThen
                   | (0xfUL << 12)  // Extend
                   | (0xfUL <<  8)  // Except_AR
                   | (0xfUL <<  4)  // Except
                   | (0xfUL <<  0)  // Endian
      );

      // ID_ISAR2_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 2,
                     (0xfUL << 28)  // Reversal
                   | (0xfUL << 24)  // PSR_AR
                   | (0xfUL << 20)  // MultU
                   | (0xfUL << 16)  // MultS
                   | (0xfUL << 12)  // Mult
                   | (0xfUL <<  8)  // MultiAccessInt
                   | (0xfUL <<  4)  // MemHint
                   | (0xfUL <<  0)  // LoadStore
      );

      // ID_ISAR3_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 3,
                     (0xfUL << 28)  // T32EE
                   | (0xfUL << 24)  // TrueNOP
                   | (0xfUL << 20)  // T32Copy
                   | (0xfUL << 16)  // TabBranch
                   | (0xfUL << 12)  // SynchPrim
                   | (0xfUL <<  8)  // SVC
                   | (0xfUL <<  4)  // SIMD
                   | (0xfUL <<  0)  // Saturate
      );

      // ID_ISAR4_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 4,
                     (0xfUL << 28)  // SWP_frac
                   | (0xfUL << 24)  // PSR_M
                   | (0xfUL << 20)  // SynchPrim_frac
                   | (0xfUL << 16)  // Barrier
                   | (0xfUL << 12)  // SMC
                   | (0xfUL <<  8)  // Writeback
                   | (0xfUL <<  4)  // WithShifts
                   | (0xfUL <<  0)  // Unpriv
      );

      // ID_ISAR5_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 5,
                     (0xfUL << 28)  // VCMA
                   | (0xfUL << 24)  // RDM
                   | (  0UL << 20)  // RES0
                   | (0xfUL << 16)  // CRC32
                   | (0xfUL << 12)  // SHA2
                   | (0xfUL <<  8)  // SHA1
                   | (0xfUL <<  4)  // AES
                   | (0xfUL <<  0)  // SEVL
      );

      // ID_MMFR4_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 6,
                     (0xfUL << 28)  // EVT
                   | (0xfUL << 24)  // CCIDX
                   | (0xfUL << 20)  // LSM
                   | (0xfUL << 16)  // HPDS
                   | (0xfUL << 12)  // CnP
                   | (0xfUL <<  8)  // XNX
                   | (0xfUL <<  4)  // AC2
                   | (  0UL <<  0)  // Mask SpecSEI (RAS)
      );

      // ID_ISAR6_EL1
      ADD_FEAT_REG(3, 0, 0, 2, 7,
                     (0xfUL << 28)  // CLRBHB
                   | (0xfUL << 24)  // I8MM
                   | (0xfUL << 20)  // BF16
                   | (0xfUL << 16)  // SPECRES
                   | (0xfUL << 12)  // SB
                   | (0xfUL <<  8)  // FHM
                   | (0xfUL <<  4)  // DP
                   | (0xfUL <<  0)  // JSCVT
      );

      // ID_MVFR0_EL1
      ADD_FEAT_REG(3, 0, 0, 3, 0,
                     (0xfUL << 28)  // FPRound
                   | (0xfUL << 24)  // FPShVec
                   | (0xfUL << 20)  // FPSqrt
                   | (0xfUL << 16)  // FPDivide
                   | (0xfUL << 12)  // FPTrap
                   | (0xfUL <<  8)  // FPDP
                   | (0xfUL <<  4)  // FPSP
                   | (0xfUL <<  0)  // SIMDReg
      );

      // ID_MVFR1_EL1
      ADD_FEAT_REG(3, 0, 0, 3, 1,
                     (0xfUL << 28)  // SIMDFMAC
                   | (0xfUL << 24)  // FPHP
                   | (0xfUL << 20)  // SIMDHP
                   | (0xfUL << 16)  // SIMDSP
                   | (0xfUL << 12)  // SIMDInt
                   | (0xfUL <<  8)  // SIMDLS
                   | (0xfUL <<  4)  // FPDNaN
                   | (0xfUL <<  0)  // FPFtZ
      );

      // ID_MVFR2_EL1
      ADD_FEAT_REG(3, 0, 0, 3, 2,
                     (0xfUL <<  4)  // FPMisc
                   | (0xfUL <<  0)  // SIMDMisc
      );

      // ID_PFR2_EL1
      ADD_FEAT_REG(3, 0, 0, 3, 4,
                     (  0UL <<  8)  // Mask RAS_frac (RAS)
                   | (0xfUL <<  4)  // SSBS
                   | (0xfUL <<  0)  // CSV3
      );

      // ID_DFR1_EL1
      ADD_FEAT_REG(3, 0, 0, 3, 5,
                     (  0UL <<  4)  // Mask HPMN0 (PMU)
                   | (  0UL <<  0)  // Mask MTPMU (PMU)
      );

      // ID_MMFR5_EL1
      ADD_FEAT_REG(3, 0, 0, 3, 6,
                     (0xfUL <<  4)  // nTLBPA
                   | (0xfUL <<  0)  // ETS
      );
    }

  // ID_AA64PFR0_EL1
  ADD_FEAT_REG(3, 0, 0, 4, 0,
                 (0xfUL << 60)  // CSV3
               | (0xfUL << 56)  // CSV2
               | (  0UL << 52)  // Mask RME
               | (0xfUL << 48)  // DIT
               | (  0UL << 44)  // Mask AMU
               | (  0UL << 40)  // Mask MPAM
               | (0xfUL << 36)  // SEL2
               | (  0UL << 32)  // Mask SVE
               | (  0UL << 28)  // Mask RAS
               | (0xfUL << 24)  // GIC
               | (0xfUL << 20)  // AdvSIMD
               | (0xfUL << 16)  // FP
               | (0xfUL << 12)  // EL3
               | (0xfUL <<  8)  // EL2
               | (0xfUL <<  4)  // EL1
               | (0xfUL <<  0)  // EL0
  );

  // ID_AA64PFR1_EL1
  ADD_FEAT_REG(3, 0, 0, 4, 1,
                 (  0UL << 60)  // Mask PFAR
               | (  0UL << 56)  // Mask DF2 (RAS related)
               | (  0UL << 52)  // Mask MTEX
               | (  0UL << 48)  // Mask THE
               | (  0UL << 44)  // Mask GCS
               | (  0UL << 40)  // Mask MTE_frac
               | (0xfUL << 36)  // NMI
               | (0xfUL << 32)  // CSV2_frac
               | (0xfUL << 28)  // RNDR_trap
               | (  0UL << 24)  // Mask SME
               | (  0UL << 20)  // RES0
               | (  0UL << 16)  // Mask MPAM_frac
               | (  0UL << 12)  // Mask RAS_frac
               | (  0UL <<  8)  // Mask MTE
               | (0xfUL <<  4)  // SSBS
               | (0xfUL <<  0)  // BT
  );

  // ID_AA64PFR2_EL1
  ADD_FEAT_REG(3, 0, 0, 4, 2,
                 (0xfUL <<  8)  // Mask MTEFAR (MTE)
               | (0xfUL <<  4)  // Mask MTESTOREONLY (MTE)
               | (0xfUL <<  0)  // Mask MTEPERM (MTE)
  );

  // ID_AA64ZFR0_EL1 skipped intentionally (SVE Feature ID Register 0)
  // ID_AA64SMFR0_EL1 skipped intentionally (SME Feature ID Register 0)

  // ID_AA64DFR0_EL1
  ADD_FEAT_REG(3, 0, 0, 5, 0,
                 (  0UL << 60)  // Mask HPMN0
               | (  0UL << 56)  // Mask ExtTrcBuff
               | (  0UL << 52)  // Mask BRBE
               | (  0UL << 48)  // Mask MTPMU
               | (  0UL << 44)  // Mask TraceBuffer
               | (  0UL << 40)  // Mask TraceFilt
               | (  0UL << 36)  // Mask DoubleLock
               | (  0UL << 32)  // Mask PMSVer
               | (  0UL << 28)  // Mask CTX_CMPs
               | (  0UL << 24)  // Mask SEBEP
               | (  0UL << 20)  // Mask WRPs
               | (  0UL << 16)  // Mask PMSS
               | (  0UL << 12)  // Mask BRPs
               | (  0UL <<  8)  // Mask PMUVer
               | (  0UL <<  4)  // Mask TraceVer
               | (0xfUL <<  0)  // DebugVer
  );

  // ID_AA64DFR1_EL1
  ADD_FEAT_REG(3, 0, 0, 5, 1,
                 (  0UL << 56)  // Mask ABL_CMPs
               | (  0UL << 52)  // Mask DPFZS
               | (  0UL << 48)  // Mask EBEP
               | (  0UL << 44)  // Mask ITE
               | (  0UL << 40)  // Mask ABLE
               | (  0UL << 36)  // Mask PMICNTR
               | (  0UL << 32)  // Mask SPMU
               | (  0UL << 24)  // Mask CTX_CMPs
               | (  0UL << 16)  // Mask WRPs
               | (  0UL <<  8)  // Mask BRPs
               | (  0UL <<  0)  // Mask SYSPMUID
  );

  // ID_AA64AFR0_EL1 skipped intentionally
  // ID_AA64AFR1_EL1 skipped intentionally

  // ID_AA64ISAR0_EL1
  ADD_FEAT_REG(3, 0, 0, 6, 0,
                 (0xfUL << 60)  // RNDR
               | (0xfUL << 56)  // TLB
               | (0xfUL << 52)  // TS
               | (0xfUL << 48)  // FHM
               | (0xfUL << 44)  // DP
               | (0xfUL << 40)  // SM4
               | (0xfUL << 36)  // SM3
               | (0xfUL << 32)  // SHA3
               | (0xfUL << 28)  // RDM
               | (0xfUL << 24)  // TME
               | (0xfUL << 20)  // Atomic
               | (0xfUL << 16)  // CRC32
               | (0xfUL << 12)  // SHA2
               | (0xfUL <<  8)  // SHA1
               | (0xfUL <<  4)  // AES
               | (  0UL <<  0)  // RES0
  );

  // ID_AA64ISAR1_EL1
  ADD_FEAT_REG(3, 0, 0, 6, 1,
                 (0xfUL << 60)  // LS64
               | (0xfUL << 56)  // XS
               | (0xfUL << 52)  // I8MM
               | (0xfUL << 48)  // DGH
               | (0xfUL << 44)  // BF16
               | (0xfUL << 40)  // SPECRES
               | (0xfUL << 36)  // SB
               | (0xfUL << 32)  // FRINTTS
               | (  0UL << 28)  // Mask GPI (FEAT_PAuth)
               | (  0UL << 24)  // Mask GPA (FEAT_PAuth)
               | (  0UL << 20)  // Mask LRCPC (FEAT_LRCPC)
               | (0xfUL << 16)  // FCMA
               | (0xfUL << 12)  // JSCVT
               | (  0UL <<  8)  // Mask API (FEAT_PAuth)
               | (  0UL <<  4)  // Mask APA (FEAT_PAuth)
               | (0xfUL <<  0)  // DPB
  );

  // ID_AA64ISAR2_EL1
  ADD_FEAT_REG(3, 0, 0, 6, 2,
                 (0xfUL << 60)  // ATS1A
               | (  0UL << 56)  // RES0
               | (0xfUL << 52)  // CSSC
               | (0xfUL << 48)  // RPRFM
               | (  0UL << 44)  // RES0
               | (0xfUL << 40)  // PRFMSLC
               | (0xfUL << 36)  // SYSINSTR_128
               | (0xfUL << 32)  // SYSREG_128
               | (0xfUL << 28)  // CLRBHB
               | (  0UL << 24)  // Mask PAC_frac (FEAT_PAuth2)
               | (0xfUL << 20)  // BC
               | (0xfUL << 16)  // MOPS
               | (  0UL << 12)  // Mask APA3 (FEAT_PAuth)
               | (  0UL <<  8)  // Mask GPA3 (FEAT_PAuth)
               | (0xfUL <<  4)  // RPRES
               | (0xfUL <<  0)  // WFxT
  );

  // ID_AA64MMFR0_EL1
  ADD_FEAT_REG(3, 0, 0, 7, 0,
                 (0xfUL << 60)  // ECV
               | (0xfUL << 56)  // FGT
               | (0xfUL << 52)  // MSA_frac
               | (0xfUL << 48)  // MSA
               | (0xfUL << 44)  // ExS
               | (0xfUL << 40)  // TGran4_2
               | (0xfUL << 36)  // TGran64_2
               | (0xfUL << 32)  // TGran16_2
               | (0xfUL << 28)  // TGran4
               | (0xfUL << 24)  // TGran64
               | (0xfUL << 20)  // TGran16
               | (0xfUL << 16)  // BigEndEL0
               | (0xfUL << 12)  // SNSMem
               | (0xfUL <<  8)  // BigEnd
               | (0xfUL <<  4)  // ASIDBits
               | (0xfUL <<  0)  // PARange
  );

  // ID_AA64MMFR1_EL1
  ADD_FEAT_REG(3, 0, 0, 7, 1,
                 (0xfUL << 60)  // ECBHB
               | (0xfUL << 56)  // CMOW
               | (0xfUL << 52)  // TIDCP1
               | (0xfUL << 48)  // nTLBPA
               | (0xfUL << 44)  // AFP
               | (0xfUL << 40)  // HCX
               | (0xfUL << 36)  // ETS
               | (0xfUL << 32)  // TWED
               | (0xfUL << 28)  // XNX
               | (  0UL << 24)  // Mask SpecSEI (RAS)
               | (0xfUL << 20)  // PAN
               | (  0UL << 16)  // Mask LO (FEAT_LOR)
               | (0xfUL << 12)  // HPDS
               | (0xfUL <<  8)  // VH
               | (0xfUL <<  4)  // VMIDBits
               | (0xfUL <<  0)  // HAFDBS
  );

  // ID_AA64MMFR2_EL1
  ADD_FEAT_REG(3, 0, 0, 7, 2,
                 (0xfUL << 60)  // E0PD
               | (0xfUL << 56)  // EVT
               | (0xfUL << 52)  // BBM
               | (0xfUL << 48)  // TTL
               | (  0UL << 44)  // RES0
               | (0xfUL << 40)  // FWB
               | (0xfUL << 36)  // IDS
               | (0xfUL << 32)  // AT
               | (0xfUL << 28)  // ST
               | (0xfUL << 24)  // NV
               | (0xfUL << 20)  // CCIDX
               | (0xfUL << 16)  // VARange
               | (  0UL << 12)  // Mask IESB (FEAT_IESB + FEAT_RAS)
               | (0xfUL <<  8)  // LSM
               | (0xfUL <<  4)  // UAO
               | (0xfUL <<  0)  // CnP
  );

  // ID_AA64MMFR3_EL1
  ADD_FEAT_REG(3, 0, 0, 7, 3,
                 (  0UL << 60)  // Mask Spec_FPACC (FEAT_PAuth++)
               | (  0UL << 56)  // Mask ADERR (RASv2)
               | (  0UL << 52)  // Mask SDERR (RASv2)
               | (  0UL << 48)  // RES0
               | (  0UL << 44)  // Mask ANERR (RASv2)
               | (  0UL << 40)  // Mask SNERR (RASv2)
               | (0xfUL << 36)  // D128_2
               | (0xfUL << 32)  // D128
               | (  0UL << 28)  // Mask MEC
               | (0xfUL << 24)  // AIE
               | (0xfUL << 20)  // S2POE
               | (0xfUL << 16)  // S1POE
               | (0xfUL << 12)  // S2PIE
               | (0xfUL <<  8)  // S1PIE
               | (0xfUL <<  4)  // SCTLRX
               | (0xfUL <<  0)  // TCRX
  );

  // ID_AA64MMFR4_EL1
  ADD_FEAT_REG(3, 0, 0, 7, 4,
               0UL << 4  // EIESB (RAS)
  );
}

}
