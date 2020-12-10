/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 */

#include <l4/util/cpu.h>

//#include "pt_walker.h"
#include "vcpu_ptr.h"

namespace Vmm {

/**
 * Decode LDRD/STRD manually.
 *
 * The LDRD/STRD "extra" load/store instructions are not decoded in HSR.
 * Instead we need to do it manually here. Just handle the LDRD/STRD
 * intructions. The decoder does *not* handle write-back because that is not
 * supported for regular LDR/STR either.
 *
 * @return The fixed-up hsr. The isv field may still be cleared in case the
 *         instruction could not be decoded.
 */
Arm::Hsr
Vcpu_ptr::decode_mmio_slowpath() const
{
  Arm::Hsr h = hsr();

  // FIXME: use a pt_walker
  //auto *vms = vm_state();
  //l4_uint32_t ip;
  //try
  //  {
  //    // overwrite the virtual IP with the physical OP code
  //    ip = get_pt_walker()->walk(*this, _s->r.ip);
  //  }
  //catch (L4::Runtime_error &e)
  //  {
  //    Dbg().printf("Could not determine opcode for MMIO access\n");
  //    return h;
  //  }

  // FIXME: Verify address range + alignment of IP?

#if !defined(CONFIG_MMU)
  if ((_s->r.flags & (1U << 5)) == 0)
    {
      // A32 instruction
      l4_uint32_t opcode = *(l4_uint32_t*)_s->r.ip;

      // Extra load/store? A regular LDR/STR is decoded by HW in HSR
      // automatically.
      if ((opcode & 0x0e000090U) != 0x90U)
        return h;

      // reject wback case
      if ((opcode & (1U << 24)) == 0 || (opcode & (1U << 21)) != 0)
        return h;

      unsigned t = (opcode >> 12) & 0xfU;
      switch (opcode & 0x100060U)
        {
        case 0x40: // LDRD
          assert(!h.pf_write());
          h.pf_isv() = 1;
          h.pf_sas() = 3; // Doubleword
          h.pf_srt() = t;
          h.pf_uvmm_srt2() = t + 1U;
          break;

        case 0x60: // STRD
          assert(h.pf_write());
          h.pf_isv() = 1;
          h.pf_sas() = 3; // Doubleword
          h.pf_srt() = t;
          h.pf_uvmm_srt2() = t + 1U;
          break;

        default:
          // All other extra load/store instructions should be decoded by HW.
          // If we end up here they use PC as source/destination. This is not
          // supported by uvmm for LDR/STR either.
          break;
        }
    }
  else
    {
      // Thumb instruction...
      l4_uint16_t opc1 = *(l4_uint16_t*)_s->r.ip;

      // Load/store dual, load/store exclusive, load-acquire/store-release,
      // and table branch group?
      if ((opc1 & 0xfe40U) != 0xe840U)
        return h;

      // Load/store dual?
      if ((opc1 & 0x0120U) == 0U)
        return h;

      // reject wback case
      if (opc1 & (1U << 5))
        return h;

      l4_uint16_t opc2 = *(l4_uint16_t*)(_s->r.ip + 2U);
      h.pf_isv() = 1;
      h.pf_sas() = 3;
      h.pf_srt() = opc2 >> 12;
      h.pf_uvmm_srt2() = (opc2 >> 8) & 0xfU;
    }
#endif

  return h;
}

}
