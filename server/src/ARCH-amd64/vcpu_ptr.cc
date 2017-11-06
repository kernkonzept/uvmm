
#include <l4/util/cpu.h>

#include "vcpu_ptr.h"
#include "vm_state_vmx.h"
#include "mad.h"
#include "pt_walker.h"

namespace Vmm {

void
Vcpu_ptr::create_state(Vcpu_ptr::Vm_state_t type)
{
  if (type == Vm_state_t::Vmx)
    _s->user_data[Reg_vmm_type] =
      reinterpret_cast<l4_umword_t>(new Vmx_state(extended_state()));
  else
    throw L4::Runtime_error(-L4_ENOSYS, "Unsupported HW virtualization type.");
}

Vcpu_ptr::Vm_state_t
Vcpu_ptr::determine_vmm_type()
{
  if (!l4util_cpu_has_cpuid())
    throw L4::Runtime_error(-L4_ENOSYS,
                            "Platform does not support CPUID. Aborting!\n");

  l4_umword_t ax, bx, cx, dx;
  l4util_cpu_cpuid(0, &ax, &bx, &cx, &dx);

  if (bx == 0x756e6547 && cx == 0x6c65746e && dx == 0x49656e69)
    return Vm_state_t::Vmx;
  else if (bx == 0x68747541 && cx == 0x444d4163 && dx == 0x69746e65)
    return Vm_state_t::Svm;
  else
    throw L4::Runtime_error(-L4_ENOSYS, "Platform not supported. Aborting!\n");
}

/// Mem_access::Kind::Other symbolises failure to decode.
Mem_access
Vcpu_ptr::decode_mmio() const
{
  Mem_access m;
  m.access = Mem_access::Other;

  auto *vms = vm_state();
  l4_uint64_t opcode;
  try
    {
      // overwrite the virtual IP with the physical OP code
      opcode = reinterpret_cast<Pt_walker *>(_s->user_data[Reg_ptw_ptr])
          ->walk(vms->cr3(), vms->ip());
    }
  catch (L4::Runtime_error &e)
    {
      Dbg().printf("Could not determine opcode for MMIO access\n");
      return m;
    }

  // amd64: vcpu regs == exc_regs
  l4_exc_regs_t *reg = reinterpret_cast<l4_exc_regs_t *>(&_s->r);
  using namespace L4mad;
  Op op;
  Desc tgt, src;
  if (0)
    Decoder().l4mad_print_insn_info(reg, opcode);

  if (!Decoder().decode(reg, opcode, &op, &tgt, &src))
    return m;

  switch(op.access_width)
    {
    case 1: m.width = Mem_access::Wd8; break;
    case 2: m.width = Mem_access::Wd16; break;
    case 4: m.width = Mem_access::Wd32; break;
    case 8: m.width = Mem_access::Wd64; break;
    default: return m;
    }

  if (tgt.dtype != L4mad::Desc_reg && tgt.dtype != L4mad::Desc_mem)
    {
      Dbg().printf("tgt type invalid %i\n", tgt.dtype);
      return m;
    }

  // SRC and TGT.val contain the register number of the MMIO access. In case of
  // write, this register can be decoded to the value.
  // In case of read I need to save the register number and write to this
  // register in writeback_mmio.

  // translate to Mem_access;
  if (op.atype == L4mad::Read)
    {
      m.access = Mem_access::Load;
      _s->user_data[Reg_mmio_read] = tgt.val >> tgt.shift;
    }
  else if (op.atype == L4mad::Write)
    {
      m.access = Mem_access::Store;
      // src.val is the register number in MAD order; which is inverse to
      // register order in l4_vcpu_regs_t.
      m.value = *decode_reg_ptr(src.val) >> src.shift;
    }
  // else unknown; Other already set.

  return m;
}

l4_umword_t *
Vcpu_ptr::decode_reg_ptr(int value) const
{
  return reinterpret_cast<l4_umword_t *>(&_s->r)
         + (L4mad::Num_registers - 1 - value);
}

} // namspace Vmm
