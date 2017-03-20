/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <arm_hyp.h>

inline void arm_subarch_setup(void *vcpu, bool guest_64bit)
{
  if (guest_64bit)
    {
      l4_umword_t hcr = l4_vcpu_e_read(vcpu, L4_VCPU_E_HCR);
      hcr |= 1UL << 31; // set RW bit
      l4_vcpu_e_write(vcpu, L4_VCPU_E_HCR, hcr);
    }
  l4_vcpu_e_write_32(vcpu, L4_VCPU_E_MDCR, 1 << 9 /*TDA*/);
}

