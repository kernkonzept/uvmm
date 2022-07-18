/*
 * Copyright (C) 2017-2018, 2021 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <arm_hyp.h>
#include <l4/re/error_helper>

inline void arm_subarch_setup(void *vcpu, bool guest_64bit, bool pmsa)
{
  if (guest_64bit)
    {
      l4_umword_t hcr = l4_vcpu_e_read(vcpu, L4_VCPU_E_HCR);
      hcr |= 1UL << 31; // set RW bit
      l4_vcpu_e_write(vcpu, L4_VCPU_E_HCR, hcr);
    }

  unsigned long id_aa64mmfr0_el1;
  asm("mrs %0, S3_0_C0_C7_0" : "=r"(id_aa64mmfr0_el1));
  unsigned msa = (id_aa64mmfr0_el1 >> 48) & 0x0fU;
  unsigned msa_frac = (id_aa64mmfr0_el1 >> 52) & 0x0fU;

  // See Armv8-R AArch64 supplement (ARM DDI 0600A)
  if (pmsa && (msa == 0 || msa != 0xf || (msa_frac != 1 && msa_frac != 2)))
    L4Re::throw_error(-L4_ENOSYS, "CPU does not support PMSA");
  else if (!pmsa && !(msa == 0 || (msa == 0xf && msa_frac == 2)))
    L4Re::throw_error(-L4_ENOSYS, "CPU does not support VMSA");

  l4_vcpu_e_write_64(vcpu, L4_VCPU_E_VTCR, pmsa ? 0 : (1ULL << 31));
}

