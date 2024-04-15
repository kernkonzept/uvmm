/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 */

#pragma once

/*
 * The constants are defined in the Intel Software Developer Manual Volume 3,
 * Appendix B.
 */

/**
 * 16-bit width VMCS fields
 */
enum Vmx_vmcs_16bit_fields
{
  /* Control fields */

  VMCS_VPID                         = 0x0000,
  VMCS_PIR_NOTIFICATION_VECTOR      = 0x0002,
  VMCS_EPTP_INDEX                   = 0x0004,
  VMCS_HLAT_PREFIX_SIZE             = 0x0006,
  VMCS_LAST_PID_PTR_INDEX           = 0x0008,

  /* Guest-state fields */

  VMCS_GUEST_ES_SELECTOR            = 0x0800,
  VMCS_GUEST_CS_SELECTOR            = 0x0802,
  VMCS_GUEST_SS_SELECTOR            = 0x0804,
  VMCS_GUEST_DS_SELECTOR            = 0x0806,
  VMCS_GUEST_FS_SELECTOR            = 0x0808,
  VMCS_GUEST_GS_SELECTOR            = 0x080a,
  VMCS_GUEST_LDTR_SELECTOR          = 0x080c,
  VMCS_GUEST_TR_SELECTOR            = 0x080e,
  VMCS_GUEST_INTERRUPT_STATUS       = 0x0810,
  VMCS_GUEST_PML_INDEX              = 0x0812,
  VMCS_GUEST_UINV                   = 0x0814,

  /* Host-state fields */

  VMCS_HOST_ES_SELECTOR             = 0x0c00,
  VMCS_HOST_CS_SELECTOR             = 0x0c02,
  VMCS_HOST_SS_SELECTOR             = 0x0c04,
  VMCS_HOST_DS_SELECTOR             = 0x0c06,
  VMCS_HOST_FS_SELECTOR             = 0x0c08,
  VMCS_HOST_GS_SELECTOR             = 0x0c0a,
  VMCS_HOST_TR_SELECTOR             = 0x0c0c,
};

/**
 * 32-bit width VMCS fields
 */
enum Vmx_vmcs_32bit_fields
{
  /* Control fields */

  VMCS_PIN_BASED_VM_EXEC_CTLS       = 0x4000,
  VMCS_PRI_PROC_BASED_VM_EXEC_CTLS  = 0x4002,
  VMCS_EXCEPTION_BITMAP             = 0x4004,
  VMCS_PAGE_FAULT_ERROR_MASK        = 0x4006,
  VMCS_PAGE_FAULT_ERROR_MATCH       = 0x4008,
  VMCS_CR3_TARGET_COUNT             = 0x400a,

  VMCS_VM_EXIT_CTLS                 = 0x400c,
  VMCS_VM_EXIT_MSR_STORE_COUNT      = 0x400e,
  VMCS_VM_EXIT_MSR_LOAD_COUNT       = 0x4010,

  VMCS_VM_ENTRY_CTLS                = 0x4012,
  VMCS_VM_ENTRY_MSR_LOAD_COUNT      = 0x4014,
  VMCS_VM_ENTRY_INTERRUPT_INFO      = 0x4016,
  VMCS_VM_ENTRY_EXCEPTION_ERROR     = 0x4018,
  VMCS_VM_ENTRY_INSN_LEN            = 0x401a,

  VMCS_TPR_THRESHOLD                = 0x401c,
  VMCS_SEC_PROC_BASED_VM_EXEC_CTLS  = 0x401e,
  VMCS_PLE_GAP                      = 0x4020,
  VMCS_PLE_WINDOW                   = 0x4022,
  VMCS_INSTRUCTION_TIMEOUT_CTRL     = 0x4024,

  /* Read-only data fields */

  VMCS_VM_INSN_ERROR                = 0x4400,
  VMCS_EXIT_REASON                  = 0x4402,
  VMCS_VM_EXIT_INTERRUPT_INFO       = 0x4404,
  VMCS_VM_EXIT_INTERRUPT_ERROR      = 0x4406,
  VMCS_IDT_VECTORING_INFO           = 0x4408,
  VMCS_IDT_VECTORING_ERROR          = 0x440a,
  VMCS_VM_EXIT_INSN_LENGTH          = 0x440c,
  VMCS_VM_EXIT_INSN_INFO            = 0x440e,

  /* Guest-state fields */

  VMCS_GUEST_ES_LIMIT               = 0x4800,
  VMCS_GUEST_CS_LIMIT               = 0x4802,
  VMCS_GUEST_SS_LIMIT               = 0x4804,
  VMCS_GUEST_DS_LIMIT               = 0x4806,
  VMCS_GUEST_FS_LIMIT               = 0x4808,
  VMCS_GUEST_GS_LIMIT               = 0x480a,
  VMCS_GUEST_LDTR_LIMIT             = 0x480c,
  VMCS_GUEST_TR_LIMIT               = 0x480e,
  VMCS_GUEST_GDTR_LIMIT             = 0x4810,
  VMCS_GUEST_IDTR_LIMIT             = 0x4812,

  VMCS_GUEST_ES_ACCESS_RIGHTS       = 0x4814,
  VMCS_GUEST_CS_ACCESS_RIGHTS       = 0x4816,
  VMCS_GUEST_SS_ACCESS_RIGHTS       = 0x4818,
  VMCS_GUEST_DS_ACCESS_RIGHTS       = 0x481a,
  VMCS_GUEST_FS_ACCESS_RIGHTS       = 0x481c,
  VMCS_GUEST_GS_ACCESS_RIGHTS       = 0x481e,
  VMCS_GUEST_LDTR_ACCESS_RIGHTS     = 0x4820,
  VMCS_GUEST_TR_ACCESS_RIGHTS       = 0x4822,

  VMCS_GUEST_INTERRUPTIBILITY_STATE = 0x4824,
  VMCS_GUEST_ACTIVITY_STATE         = 0x4826,
  VMCS_GUEST_SMBASE                 = 0x4828,
  VMCS_GUEST_IA32_SYSENTER_CS       = 0x482a,
  VMCS_PREEMPTION_TIMER_VALUE       = 0x482e,

  /* Host-state fields */

  VMCS_HOST_IA32_SYSENTER_CS        = 0x4c00,
};

/**
 * Natural-width VMCS fields
 */
enum Vmx_vmcs_natural_fields
{
  /* Control fields */

  VMCS_CR0_GUEST_HOST_MASK          = 0x6000,
  VMCS_CR4_GUEST_HOST_MASK          = 0x6002,
  VMCS_CR0_READ_SHADOW              = 0x6004,
  VMCS_CR4_READ_SHADOW              = 0x6006,
  VMCS_CR3_TARGET_VALUE0            = 0x6008,
  VMCS_CR3_TARGET_VALUE1            = 0x600a,
  VMCS_CR3_TARGET_VALUE2            = 0x600c,
  VMCS_CR3_TARGET_VALUE3            = 0x600e,

  /* Read-only data fields */

  VMCS_EXIT_QUALIFICATION           = 0x6400,
  VMCS_IO_RCX                       = 0x6402,
  VMCS_IO_RSI                       = 0x6404,
  VMCS_IO_RDI                       = 0x6406,
  VMCS_IO_RIP                       = 0x6408,
  VMCS_GUEST_LINEAR_ADDRESS         = 0x640a,

  /* Guest-state fields */

  VMCS_GUEST_CR0                    = 0x6800,
  VMCS_GUEST_CR3                    = 0x6802,
  VMCS_GUEST_CR4                    = 0x6804,
  VMCS_GUEST_ES_BASE                = 0x6806,
  VMCS_GUEST_CS_BASE                = 0x6808,
  VMCS_GUEST_SS_BASE                = 0x680a,
  VMCS_GUEST_DS_BASE                = 0x680c,
  VMCS_GUEST_FS_BASE                = 0x680e,
  VMCS_GUEST_GS_BASE                = 0x6810,
  VMCS_GUEST_LDTR_BASE              = 0x6812,
  VMCS_GUEST_TR_BASE                = 0x6814,
  VMCS_GUEST_GDTR_BASE              = 0x6816,
  VMCS_GUEST_IDTR_BASE              = 0x6818,
  VMCS_GUEST_DR7                    = 0x681a,
  VMCS_GUEST_RSP                    = 0x681c,
  VMCS_GUEST_RIP                    = 0x681e,
  VMCS_GUEST_RFLAGS                 = 0x6820,
  VMCS_GUEST_PENDING_DBG_EXCEPTIONS = 0x6822,
  VMCS_GUEST_IA32_SYSENTER_ESP      = 0x6824,
  VMCS_GUEST_IA32_SYSENTER_EIP      = 0x6826,
  VMCS_GUEST_IA32_S_CET             = 0x6828,
  VMCS_GUEST_SSP                    = 0x682a,
  VMCS_GUEST_IA32_INTR_SSP_TBL_ADDR = 0x682c,

  /* Host-state fields */

  VMCS_HOST_CR0                     = 0x6c00,
  VMCS_HOST_CR3                     = 0x6c02,
  VMCS_HOST_CR4                     = 0x6c04,
  VMCS_HOST_FS_BASE                 = 0x6c06,
  VMCS_HOST_GS_BASE                 = 0x6c08,
  VMCS_HOST_TR_BASE                 = 0x6c0a,
  VMCS_HOST_GDTR_BASE               = 0x6c0c,
  VMCS_HOST_IDTR_BASE               = 0x6c0e,
  VMCS_HOST_IA32_SYSENTER_ESP       = 0x6c10,
  VMCS_HOST_IA32_SYSENTER_EIP       = 0x6c12,
  VMCS_HOST_RSP                     = 0x6c14,
  VMCS_HOST_RIP                     = 0x6c16,
  VMCS_HOST_IA32_S_CET              = 0x6c18,
  VMCS_HOST_SSP                     = 0x6c1a,
  VMCS_HOST_IA32_INTR_SSP_TBL_ADDR  = 0x6c1c,
};

/**
 * 64-bit width VMCS fields
 */
enum Vmx_vmcs_64bit_fields
{
  /* Control fields */

  VMCS_ADDRESS_IO_BITMAP_A          = 0x2000,
  VMCS_ADDRESS_IO_BITMAP_B          = 0x2002,
  VMCS_ADDRESS_MSR_BITMAP           = 0x2004,
  VMCS_VM_EXIT_MSR_STORE_ADDRESS    = 0x2006,
  VMCS_VM_EXIT_MSR_LOAD_ADDRESS     = 0x2008,
  VMCS_VM_ENTRY_MSR_LOAD_ADDRESS    = 0x200a,
  VMCS_EXECUTIVE_VMCS_POINTER       = 0x200c,
  VMCS_TSC_OFFSET                   = 0x2010,
  VMCS_VIRTUAL_APIC_ADDRESS         = 0x2012,
  VMCS_APIC_ACCESS_ADDRESS          = 0x2014,
  VMCS_PIR_DESCRIPTOR               = 0x2016,
  VMCS_VM_FUNCTION_CONTROL          = 0x2018,
  VMCS_EPT_POINTER                  = 0x201a,
  VMCS_EOI_EXIT_BITMAP0             = 0x201c,
  VMCS_EOI_EXIT_BITMAP1             = 0x201e,
  VMCS_EOI_EXIT_BITMAP2             = 0x2020,
  VMCS_EOI_EXIT_BITMAP3             = 0x2022,
  VMCS_EPTP_LIST_ADDRESS            = 0x2024,
  VMCS_VMREAD_BITMAP_ADDRESS        = 0x2026,
  VMCS_VMWRITE_BITMAP_ADDRESS       = 0x2028,
  VMCS_VIRT_EXCP_INFO_ADDRESS       = 0x202a,
  VMCS_XSS_EXITING_BITMAP           = 0x202c,
  VMCS_ENCLS_EXITING_BITMAP         = 0x202e,
  VMCS_SUBPAGE_PERMISSION_TBL_PTR   = 0x2030,
  VMCS_TSC_MULTIPLIER               = 0x2032,
  VMCS_TER_PROC_BASED_VM_EXEC_CTLS  = 0x2034,
  VMCS_ENCLV_EXITING_BITMAP         = 0x2036,
  VMCS_LOW_PASID_DIR_ADDRESS        = 0x2038,
  VMCS_HIGH_PASID_DIR_ADDRESS       = 0x203a,
  VMCS_SHARED_EPT_POINTER           = 0x203c,
  VMCS_PCONFIG_EXITING_BITMAP       = 0x203e,
  VMCS_HLATP                        = 0x2040,
  VMCS_PID_POINTER_TABLE_ADDRESS    = 0x2042,
  VMCS_SEC_VM_EXIT_CTLS             = 0x2044,
  VMCS_IA32_SPEC_CTRL_MASK          = 0x204a,
  VMCS_IA32_SPEC_CTRL_SHADOW        = 0x204c,

  /* Read-only data fields */

  VMCS_GUEST_PHYSICAL_ADDRESS       = 0x2400,

  /* Guest-state fields */

  VMCS_LINK_POINTER                 = 0x2800,
  VMCS_GUEST_IA32_DEBUGCTL          = 0x2802,
  VMCS_GUEST_IA32_PAT               = 0x2804,
  VMCS_GUEST_IA32_EFER              = 0x2806,
  VMCS_GUEST_IA32_PERF_GLOBAL_CTRL  = 0x2808,
  VMCS_GUEST_PDPTE0                 = 0x280a,
  VMCS_GUEST_PDPTE1                 = 0x280c,
  VMCS_GUEST_PDPTE2                 = 0x280e,
  VMCS_GUEST_PDPTE3                 = 0x2810,
  VMCS_GUEST_IA32_BNDCFGS           = 0x2812,
  VMCS_GUEST_IA32_RTIT_CTL          = 0x2814,
  VMCS_GUEST_IA32_LBR_CTL           = 0x2816,
  VMCS_GUEST_IA32_PKRS              = 0x2818,

  /* Host-state fields */

  VMCS_HOST_IA32_PAT                = 0x2c00,
  VMCS_HOST_IA32_EFER               = 0x2c02,
  VMCS_HOST_IA32_PERF_GLOBAL_CTRL   = 0x2c04,
  VMCS_HOST_IA32_PKRS               = 0x2c06,
};
