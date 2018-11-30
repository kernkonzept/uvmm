/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "mmio_device.h"
#include "arm_hyp.h"
#include "debug.h"
#include "vcpu.h"

static Dbg mmio_msg(Dbg::Mmio, "mmio");

namespace Vmm {

struct Mmio_device_t_b
{
  bool decode_mmio(Arm::Hsr hsr, l4_umword_t **gpr, Cpu vcpu)
  {
    if (!hsr.pf_isv())
      {
        Err().printf("undecoded device access\n");
        // dump state
        return false;
      }

    if (hsr.pf_srt() < 13)
      *gpr = &vcpu->r.r[hsr.pf_srt()];
    else
      {
        switch (hsr.pf_srt())
          {
          case 13: *gpr = &vcpu->r.sp; break;
          case 14: *gpr = &vcpu->r.lr; break;
          default: Err().printf("Unsupported mmio register %d\n",
                                (unsigned)hsr.pf_srt());
                   return false;
          }
      }

    return true;
  }

};

template<typename T>
struct Mmio_device_t : Mmio_device, Mmio_device_t_b
{
  bool access(l4_addr_t pfa, l4_addr_t offset, Cpu vcpu,
              L4::Cap<L4::Task>, l4_addr_t, l4_addr_t)
  {
    Arm::Hsr hsr(vcpu->r.err);
    l4_umword_t *gpr;
    if (this->decode_mmio(hsr, &gpr, vcpu))
      {
        // skip insn
        vcpu->r.ip += 2 << hsr.il();

        // TODO: provide accessor for correct mode + register
        if (hsr.pf_write())
          {
            mmio_msg.printf("write %08lx+%05lx (%d) value: %08lx (r=%d)\n",
                            pfa - offset, offset,
                            (unsigned)hsr.pf_sas(), *gpr,
                            (unsigned)hsr.pf_srt());
            static_cast<T *>(this)->write(offset, hsr.pf_sas(), *gpr, vcpu.get_vcpu_id());
          }
        else
          {
            l4_uint32_t res = static_cast<T*>(this)->read(offset, hsr.pf_sas(),
                                                          vcpu.get_vcpu_id());
            if (hsr.pf_sse())
              {
                switch (hsr.pf_sas())
                  {
                  case 0:  res = (l4_int32_t)((l4_int8_t)res);
                           break;
                  case 1:  res = (l4_int32_t)((l4_int16_t)res);
                           break;
                  default: break;
                  }
              }

              mmio_msg.printf("read  %08lx+%05lx (%d) value: %08x (r=%d)\n",
                              pfa - offset, offset,
                              (unsigned)hsr.pf_sas(), res,
                              (unsigned)hsr.pf_srt());
            *gpr = res;
          }
      }
    else
      {
        // skip insn
        vcpu->r.ip += 2 << hsr.il();
      }

    return true;
  }
};

}
