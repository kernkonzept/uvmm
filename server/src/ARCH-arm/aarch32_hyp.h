#pragma once

#include <arm_hyp.h>

namespace Vmm { namespace Arm {

struct State
{
  struct Per_mode_regs
  {
    l4_umword_t sp;
    l4_umword_t lr;
    l4_umword_t spsr;
  };

  struct Regs
  {
    l4_uint32_t hcr;

    l4_uint64_t ttbr0;
    l4_uint64_t ttbr1;
    l4_uint32_t ttbcr;
    l4_uint32_t sctlr;
    l4_uint32_t dacr;
    l4_uint32_t fcseidr;
    l4_uint32_t contextidr;
    l4_uint32_t cntkctl;
  };

  typedef Gic_t<4> Gic;

  Regs vm_regs;
  Regs host_regs;
  Gic  gic;

  l4_uint64_t cntvoff;

  l4_uint64_t cntv_cval;
  l4_uint32_t cntkctl;
  l4_uint32_t cntv_ctl;

  l4_uint32_t vmpidr;

  void arch_setup(bool)
  {}
};

inline State *
vm_state(l4_vcpu_state_t *vcpu)
{
  return reinterpret_cast<State *>(reinterpret_cast<char *>(vcpu) + L4_VCPU_OFFSET_EXT_STATE);
}

}}
