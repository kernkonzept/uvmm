/*
 * Copyright (C) 2024-2025 Kernkonzept GmbH.
 * Author(s): Steffen Liebergeld <steffen.liebergeld@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

/**
 * \file
 * This file defines the x86 CPU features that we present to the guest via
 * our CPUID emulation.
 *
 * General rules:
 * - Whitelist only those CPU features that we know to support.
 * - We shall support as many features as possible because they might be there
 *   for performance.
 */

namespace
{

enum Cpuid_1_ecx : l4_uint32_t
{
  Cpuid_1_ecx_sse3            = (1UL << 0),
  Cpuid_1_ecx_pclmulqdq       = (1UL << 1),
  Cpuid_1_ecx_dtes64          = (1UL << 2),
  Cpuid_1_ecx_monitor         = (1UL << 3),
  Cpuid_1_ecx_ds_cpl          = (1UL << 4),
  Cpuid_1_ecx_vmx             = (1UL << 5),
  Cpuid_1_ecx_smx             = (1UL << 6),
  Cpuid_1_ecx_speed_step      = (1UL << 7),
  Cpuid_1_ecx_thermal_monitor = (1UL << 8),
  Cpuid_1_ecx_ssse3           = (1UL << 9),
  Cpuid_1_ecx_context_id      = (1UL << 10),
  Cpuid_1_ecx_sdbg            = (1UL << 11),
  Cpuid_1_ecx_fma             = (1UL << 12),
  Cpuid_1_ecx_cmpxchg16b      = (1UL << 13),
  Cpuid_1_ecx_xtpr_update     = (1UL << 14),
  Cpuid_1_ecx_pdcm            = (1UL << 15),
  Cpuid_1_ecx_pcid            = (1UL << 17),
  Cpuid_1_ecx_dca             = (1UL << 18),
  Cpuid_1_ecx_sse4_1          = (1UL << 19),
  Cpuid_1_ecx_sse4_2          = (1UL << 20),
  Cpuid_1_ecx_x2apic          = (1UL << 21),
  Cpuid_1_ecx_movbe           = (1UL << 22),
  Cpuid_1_ecx_popcnt          = (1UL << 23),
  Cpuid_1_ecx_tsc_deadline    = (1UL << 24),
  Cpuid_1_ecx_aesni           = (1UL << 25),
  Cpuid_1_ecx_xsave           = (1UL << 26),
  Cpuid_1_ecx_osxsave         = (1UL << 27),
  Cpuid_1_ecx_avx             = (1UL << 28),
  Cpuid_1_ecx_f16c            = (1UL << 29),
  Cpuid_1_ecx_rdrand          = (1UL << 30),
  Cpuid_1_ecx_hypervisor      = (1UL << 31),
};

enum Cpuid_1_edx : l4_uint32_t
{
  Cpuid_1_edx_fpu   = (1UL << 0),
  Cpuid_1_edx_vme   = (1UL << 1),
  Cpuid_1_edx_de    = (1UL << 2),
  Cpuid_1_edx_pse   = (1UL << 3),
  Cpuid_1_edx_tsc   = (1UL << 4),
  Cpuid_1_edx_msr   = (1UL << 5),
  Cpuid_1_edx_pae   = (1UL << 6),
  Cpuid_1_edx_mce   = (1UL << 7),
  Cpuid_1_edx_cx8   = (1UL << 8),
  Cpuid_1_edx_apic  = (1UL << 9),
  Cpuid_1_edx_sep   = (1UL << 11),
  Cpuid_1_edx_mtrr  = (1UL << 12),
  Cpuid_1_edx_pge   = (1UL << 13),
  Cpuid_1_edx_mca   = (1UL << 14),
  Cpuid_1_edx_cmov  = (1UL << 15),
  Cpuid_1_edx_pat   = (1UL << 16),
  Cpuid_1_edx_pse_36= (1UL << 17),
  Cpuid_1_edx_psn   = (1UL << 18),
  Cpuid_1_edx_clfsh = (1UL << 19),
  Cpuid_1_edx_ds    = (1UL << 21),
  Cpuid_1_edx_acpi  = (1UL << 22),
  Cpuid_1_edx_mmx   = (1UL << 23),
  Cpuid_1_edx_fxsr  = (1UL << 24),
  Cpuid_1_edx_sse   = (1UL << 25),
  Cpuid_1_edx_sse2  = (1UL << 26),
  Cpuid_1_edx_ss    = (1UL << 27),
  Cpuid_1_edx_htt   = (1UL << 28),
  Cpuid_1_edx_tm    = (1UL << 29),
  Cpuid_1_edx_pbe   = (1UL << 31),

};

// thermal and power management
enum Cpuid_6_eax : l4_uint32_t
{
  Cpuid_6_eax_temp_sens            = (1UL << 0),
  Cpuid_6_eax_turbo_boost          = (1UL << 1),
  Cpuid_6_eax_arat                 = (1UL << 2),
  Cpuid_6_eax_pln                  = (1UL << 4),
  Cpuid_6_eax_ecmd                 = (1UL << 5),
  Cpuid_6_eax_ptm                  = (1UL << 6),
  Cpuid_6_eax_hwp                  = (1UL << 7),
  Cpuid_6_eax_hwp_notify           = (1UL << 8),
  Cpuid_6_eax_hwp_act_win          = (1UL << 9),
  Cpuid_6_eax_hwp_energy_perf_pref = (1UL << 10),
  Cpuid_6_eax_hwp_package_level    = (1UL << 11),
  Cpuid_6_eax_hdc                  = (1UL << 13),
  Cpuid_6_eax_turbo_boost_max      = (1UL << 14),
  Cpuid_6_eax_hwp_capabilities     = (1UL << 15),
  Cpuid_6_eax_hwp_peci             = (1UL << 16),
  Cpuid_6_eax_hwp_flex             = (1UL << 17),
  Cpuid_6_eax_hwp_request_msr      = (1UL << 18),
  Cpuid_6_eax_hw_feedback          = (1UL << 19),
  Cpuid_6_eax_ignore_idle_cpu_hwp  = (1UL << 20),
  Cpuid_6_eax_hwp_control_msr      = (1UL << 22),
  Cpuid_6_eax_thread_director      = (1UL << 23),
  Cpuid_6_eax_therm_irq_msr        = (1UL << 24),
};

enum Cpuid_7_0_ebx : l4_uint32_t
{
  Cpuid_7_0_ebx_fsgsbase       = (1UL << 0),
  Cpuid_7_0_ebx_tsc_adjust_msr = (1UL << 1),
  Cpuid_7_0_ebx_sgx            = (1UL << 2),
  Cpuid_7_0_ebx_bmi1           = (1UL << 3),
  Cpuid_7_0_ebx_hle            = (1UL << 4),
  Cpuid_7_0_ebx_avx2           = (1UL << 5),
  Cpuid_7_0_ebx_fdp_excptn_only= (1UL << 6),
  Cpuid_7_0_ebx_smep           = (1UL << 7),
  Cpuid_7_0_ebx_bmi2           = (1UL << 8),
  Cpuid_7_0_ebx_movsb          = (1UL << 9),
  Cpuid_7_0_ebx_invpcid        = (1UL << 10),
  Cpuid_7_0_ebx_rtm            = (1UL << 11),
  Cpuid_7_0_ebx_rdt_m          = (1UL << 12),
  Cpuid_7_0_ebx_fpu_cs         = (1UL << 13),
  Cpuid_7_0_ebx_mpx            = (1UL << 14),
  Cpuid_7_0_ebx_rdt_a          = (1UL << 15),
  Cpuid_7_0_ebx_avx_512_f      = (1UL << 16),
  Cpuid_7_0_ebx_avx_512_dq     = (1UL << 17),
  Cpuid_7_0_ebx_rdseed         = (1UL << 18),
  Cpuid_7_0_ebx_adx            = (1UL << 19),
  Cpuid_7_0_ebx_smap           = (1UL << 20),
  Cpuid_7_0_ebx_avx_512_ifma   = (1UL << 21),
  Cpuid_7_0_ebx_clflushopt     = (1UL << 23),
  Cpuid_7_0_ebx_clwb           = (1UL << 24),
  Cpuid_7_0_ebx_trace          = (1UL << 25),
  Cpuid_7_0_ebx_avx_512_pf     = (1UL << 26),
  Cpuid_7_0_ebx_avx_512_er     = (1UL << 27),
  Cpuid_7_0_ebx_avx_512_cd     = (1UL << 28),
  Cpuid_7_0_ebx_sha            = (1UL << 29),
  Cpuid_7_0_ebx_avx_512_bw     = (1UL << 30),
  Cpuid_7_0_ebx_avx_512_vl     = (1UL << 31),
};

enum Cpuid_7_0_ecx : l4_uint32_t
{
  Cpuid_7_0_ecx_prefetchwt1      = (1UL << 0),
  Cpuid_7_0_ecx_avx_512_vbmi     = (1UL << 1),
  Cpuid_7_0_ecx_umip             = (1UL << 2),
  Cpuid_7_0_ecx_pku              = (1UL << 3),
  Cpuid_7_0_ecx_ospke            = (1UL << 4),
  Cpuid_7_0_ecx_waitpkg          = (1UL << 5),
  Cpuid_7_0_ecx_avx_512_vbmi2    = (1UL << 6),
  Cpuid_7_0_ecx_cet_ss           = (1UL << 7),
  Cpuid_7_0_ecx_gfni             = (1UL << 8),
  Cpuid_7_0_ecx_vaes             = (1UL << 9),
  Cpuid_7_0_ecx_vpclmulqdq       = (1UL << 10),
  Cpuid_7_0_ecx_avx_512_vnni     = (1UL << 11),
  Cpuid_7_0_ecx_avx_512_bitalg   = (1UL << 12),
  Cpuid_7_0_ecx_tme_en           = (1UL << 13),
  Cpuid_7_0_ecx_avx_512_vpopcntdq= (1UL << 14),
  Cpuid_7_0_ecx_la57             = (1UL << 16),
  Cpuid_7_0_ecx_rdpid            = (1UL << 22),
  Cpuid_7_0_ecx_kl               = (1UL << 23),
  Cpuid_7_0_ecx_bus_lock_detect  = (1UL << 24),
  Cpuid_7_0_ecx_cldemote         = (1UL << 25),
  Cpuid_7_0_ecx_movdiri          = (1UL << 27),
  Cpuid_7_0_ecx_movdir64b        = (1UL << 28),
  Cpuid_7_0_ecx_enqcmd           = (1UL << 29),
  Cpuid_7_0_ecx_sgx_lc           = (1UL << 30),
  Cpuid_7_0_ecx_pks              = (1UL << 31),
};

enum Cpuid_7_0_edx : l4_uint32_t
{
  Cpuid_7_0_edx_sgx_keys            = (1UL << 1),
  Cpuid_7_0_edx_avx_512_4vnniw      = (1UL << 2),
  Cpuid_7_0_edx_avx_512_4fmaps      = (1UL << 3),
  Cpuid_7_0_edx_repmov              = (1UL << 4),
  Cpuid_7_0_edx_uintr               = (1UL << 5),
  Cpuid_7_0_edx_avx_512_vp2intersect= (1UL << 8),
  Cpuid_7_0_edx_srbds_ctrl          = (1UL << 9),
  Cpuid_7_0_edx_md_clear            = (1UL << 10),
  Cpuid_7_0_edx_rtm_always_abort    = (1UL << 11),
  Cpuid_7_0_edx_rtm_force_abort     = (1UL << 13),
  Cpuid_7_0_edx_serialize           = (1UL << 14),
  Cpuid_7_0_edx_hybrid              = (1UL << 15),
  Cpuid_7_0_edx_tsxldtrk            = (1UL << 16),
  Cpuid_7_0_edx_pconfig             = (1UL << 18),
  Cpuid_7_0_edx_arch_lbr            = (1UL << 19),
  Cpuid_7_0_edx_cet_ibt             = (1UL << 20),
  Cpuid_7_0_edx_amx_fb16            = (1UL << 22),
  Cpuid_7_0_edx_avx_512_fp16        = (1UL << 23),
  Cpuid_7_0_edx_amx_tile            = (1UL << 24),
  Cpuid_7_0_edx_amx_int8            = (1UL << 25),
  Cpuid_7_0_edx_ibrs                = (1UL << 26),
  Cpuid_7_0_edx_stibp               = (1UL << 27),
  Cpuid_7_0_edx_l1d_flush           = (1UL << 28),
  Cpuid_7_0_edx_arch_cap_msr        = (1UL << 29),
  Cpuid_7_0_edx_core_cap_msr        = (1UL << 30),
  Cpuid_7_0_edx_ssbd                = (1UL << 31),
};

enum Cpuid_8000_0001_ecx : l4_uint32_t
{
  // TODO amd has several bits here
  Cpuid_8000_0001_ecx_lahf      = (1UL << 0),
  Cpuid_8000_0001_ecx_lzcnt     = (1UL << 5),
  Cpuid_8000_0001_ecx_prefetchw = (1UL << 8),
};

enum Cpuid_8000_0001_edx : l4_uint32_t
{
  Cpuid_8000_0001_edx_syscall  = (1UL << 11),
  Cpuid_8000_0001_edx_nx       = (1UL << 20),
  Cpuid_8000_0001_edx_1gb      = (1UL << 26),
  Cpuid_8000_0001_edx_rdtscp   = (1UL << 27),
  Cpuid_8000_0001_edx_ia64     = (1UL << 29),
};

enum Cpuid_8000_0007_edx : l4_uint32_t
{
  Cpuid_8000_0007_edx_invariant_tsc = (1UL << 8),
};

enum Cpuid_8000_0008_ebx : l4_uint32_t
{
  Cpuid_8000_0008_ebx_amd_clzero         = (1UL << 0),
  Cpuid_8000_0008_ebx_amd_instretcnt_msr = (1UL << 1),
  Cpuid_8000_0008_ebx_amd_rstrfperrptrs  = (1UL << 2),
  Cpuid_8000_0008_ebx_amd_invlpkg        = (1UL << 3),
  Cpuid_8000_0008_ebx_amd_rdpru          = (1UL << 4),
  Cpuid_8000_0008_ebx_amd_mcommit        = (1UL << 8),
  Cpuid_8000_0008_ebx_wbnoinvd           = (1UL << 9),
  // AMD speculation control.
  // 0x8000'0008 EBX
  // Whitepaper AMD64 Technology: Indirect Branch Control Extension,
  // revision 4.10.18
  Cpuid_8000_0008_ebx_amd_ibpb           = (1UL << 12),
  Cpuid_8000_0008_ebx_amd_ibrs           = (1UL << 14),
  Cpuid_8000_0008_ebx_amd_stibp          = (1UL << 15),
  // Whitepaper AMD64 Technology: Speculative Store Bypass Disable, 5.21.18
  Cpuid_8000_0008_ebx_amd_ssbd           = (1UL << 24),
};

}; // namespace

namespace Vmm
{
enum Cpuid_configuration : l4_uint32_t
{
  // general config
  Cpuid_max_basic_info_leaf = 0x1f,
  Cpuid_max_ext_info_leaf   = 0x8000'0008,

  // leaf config

  // Unsupported:
  //   Cpuid_1_ecx_monitor
  //   Cpuid_1_ecx_vmx
  //   Cpuid_1_ecx_smx
  //   Cpuid_1_ecx_thermal_monitor
  //   Cpuid_1_ecx_speed_step
  //   Cpuid_1_ecx_sdbg
  //   Cpuid_1_ecx_osxsave
  //   Cpuid_1_ecx_xtpr_update
  //   Cpuid_1_ecx_pdcm
  //   Cpuid_1_ecx_context_id
  //   Cpuid_1_ecx_dca
  //   Cpuid_1_ecx_ds_cpl
  //   Cpuid_1_ecx_dtes64

  Cpuid_1_ecx_supported = \
    Cpuid_1_ecx_sse3 \
    | Cpuid_1_ecx_pclmulqdq \
    | Cpuid_1_ecx_ssse3 \
    | Cpuid_1_ecx_fma \
    | Cpuid_1_ecx_cmpxchg16b \
    | Cpuid_1_ecx_sse4_1 \
    | Cpuid_1_ecx_sse4_2 \
    | Cpuid_1_ecx_movbe \
    | Cpuid_1_ecx_popcnt \
    | Cpuid_1_ecx_tsc_deadline \
    | Cpuid_1_ecx_aesni \
    | Cpuid_1_ecx_xsave \
    | Cpuid_1_ecx_avx \
    | Cpuid_1_ecx_f16c \
    | Cpuid_1_ecx_pcid \
    | Cpuid_1_ecx_rdrand,

  Cpuid_1_ecx_mandatory = \
    Cpuid_1_ecx_hypervisor
    // x2apic is emulated even if the host doesn't have it
    | Cpuid_1_ecx_x2apic,

  // Unsupported flags
  //  Cpuid_1_edx_mca
  //  Cpuid_1_edx_acpi
  //  Cpuid_1_edx_ds
  //  Cpuid_1_edx_tm
  //  Cpuid_1_edx_psn
  //  Cpuid_1_edx_pbe
  Cpuid_1_edx_supported = \
    Cpuid_1_edx_fpu \
    | Cpuid_1_edx_vme \
    | Cpuid_1_edx_de  \
    | Cpuid_1_edx_pse \
    | Cpuid_1_edx_tsc \
    | Cpuid_1_edx_msr \
    | Cpuid_1_edx_pae \
    | Cpuid_1_edx_mce \
    | Cpuid_1_edx_cx8 \
    | Cpuid_1_edx_apic\
    | Cpuid_1_edx_sep \
    | Cpuid_1_edx_mtrr\
    | Cpuid_1_edx_pge \
    | Cpuid_1_edx_cmov\
    | Cpuid_1_edx_pat \
    | Cpuid_1_edx_pse_36 \
    | Cpuid_1_edx_clfsh \
    | Cpuid_1_edx_mmx \
    | Cpuid_1_edx_fxsr \
    | Cpuid_1_edx_sse \
    | Cpuid_1_edx_sse2 \
    | Cpuid_1_edx_ss \
    | Cpuid_1_edx_htt,

  Cpuid_6_eax_supported  = \
    Cpuid_6_eax_arat,

  Cpuid_7_0_eax_leafs = 1,

  // Unsupported:
  //   Cpuid_7_0_ebx_mpx
  //   Cpuid_7_0_ebx_trace
  Cpuid_7_0_ebx_supported = \
    Cpuid_7_0_ebx_fsgsbase \
    | Cpuid_7_0_ebx_bmi1 \
    | Cpuid_7_0_ebx_hle \
    | Cpuid_7_0_ebx_avx2 \
    | Cpuid_7_0_ebx_fdp_excptn_only \
    | Cpuid_7_0_ebx_smep \
    | Cpuid_7_0_ebx_bmi2 \
    | Cpuid_7_0_ebx_movsb \
    | Cpuid_7_0_ebx_rtm \
    | Cpuid_7_0_ebx_fpu_cs \
    | Cpuid_7_0_ebx_avx_512_f \
    | Cpuid_7_0_ebx_avx_512_dq \
    | Cpuid_7_0_ebx_rdseed \
    | Cpuid_7_0_ebx_adx \
    | Cpuid_7_0_ebx_smap \
    | Cpuid_7_0_ebx_avx_512_ifma \
    | Cpuid_7_0_ebx_clflushopt \
    | Cpuid_7_0_ebx_clwb \
    | Cpuid_7_0_ebx_avx_512_pf \
    | Cpuid_7_0_ebx_avx_512_er \
    | Cpuid_7_0_ebx_avx_512_cd \
    | Cpuid_7_0_ebx_sha \
    | Cpuid_7_0_ebx_invpcid \
    | Cpuid_7_0_ebx_avx_512_bw \
    | Cpuid_7_0_ebx_avx_512_vl,

  // Unsupported:
  //   Cpuid_7_0_ecx_ospke
  //   Cpuid_7_0_ecx_waitpkg
  //   Cpuid_7_0_ecx_la57 (ia32e 5 level paging)
  Cpuid_7_0_ecx_supported  = \
    Cpuid_7_0_ecx_prefetchwt1 \
    | Cpuid_7_0_ecx_avx_512_vbmi \
    | Cpuid_7_0_ecx_umip \
    | Cpuid_7_0_ecx_avx_512_vbmi2 \
    | Cpuid_7_0_ecx_avx_512_vnni \
    | Cpuid_7_0_ecx_avx_512_bitalg,

  Cpuid_7_0_edx_supported = \
    Cpuid_7_0_edx_avx_512_4vnniw \
    | Cpuid_7_0_edx_avx_512_4fmaps \
    | Cpuid_7_0_edx_repmov \
    | Cpuid_7_0_edx_avx_512_vp2intersect \
    | Cpuid_7_0_edx_avx_512_fp16 \
    | Cpuid_7_0_edx_uintr \
    | Cpuid_7_0_edx_md_clear,

  Cpuid_8000_0001_ecx_supported = \
    Cpuid_8000_0001_ecx_lahf,

  Cpuid_8000_0001_edx_supported = \
    Cpuid_8000_0001_edx_syscall \
    | Cpuid_8000_0001_edx_nx \
    | Cpuid_8000_0001_edx_1gb \
    | Cpuid_8000_0001_edx_ia64,

  Cpuid_8000_0007_edx_supported = \
    Cpuid_8000_0007_edx_invariant_tsc,

  // According to the Linux source code at arch/x86/kernel/cpu/common.c,
  // "[...] a hypervisor might have set the individual AMD bits even on
  // Intel CPUs, for finer-grained selection of what's available."
  // Thus filter AMD bits for the case of nested virtualization.
  Cpuid_8000_0008_ebx_supported = \
    Cpuid_8000_0008_ebx_wbnoinvd,
};

inline void
cpuid_reg_apply(l4_uint32_t *host_register,
                l4_uint32_t  supported_bits,
                l4_uint32_t  mandatory_bits = 0)
{
  *host_register &= supported_bits;
  *host_register |= mandatory_bits;
}

}; // namespace Vmm
