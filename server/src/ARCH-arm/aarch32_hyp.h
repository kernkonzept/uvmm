#pragma once

#include <arm_hyp.h>
#include <l4/re/error_helper>

inline void arm_subarch_setup(void *, bool, bool pmsa)
{
  unsigned long id_mmfr0;
  asm ("mrc p15, 0, %0, c0, c1, 4": "=r" (id_mmfr0));

  if (pmsa && (id_mmfr0 & 0xf0) == 0)
    L4Re::throw_error(-L4_ENOSYS, "CPU does not support PMSA");
  else if (!pmsa && (id_mmfr0 & 0x0f) == 0)
    L4Re::throw_error(-L4_ENOSYS, "CPU does not support VMSA");
}
