/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017, 2019, 2021-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 */

#include <l4/util/cpu.h>

#include "vcpu_ptr.h"
#include "vm_state_svm.h"
#include "vm_state_vmx.h"
#include "pt_walker.h"
#include "mad.h"
#include "guest.h"

namespace Vmm {

void
Vcpu_ptr::create_state(Vm_state::Type type)
{
  if (type == Vm_state::Type::Vmx)
    _s->user_data[Reg_vmm_type] =
      reinterpret_cast<l4_umword_t>(new Vmx_state(extended_state()));
  else if(type == Vm_state::Type::Svm)
    _s->user_data[Reg_vmm_type] =
      reinterpret_cast<l4_umword_t>(new Svm_state(extended_state()));

  else
    throw L4::Runtime_error(-L4_ENOSYS, "Unsupported HW virtualization type.");
}

Vm_state::Type
Vcpu_ptr::determine_vmm_type()
{
  if (!l4util_cpu_has_cpuid())
    throw L4::Runtime_error(-L4_ENOSYS,
                            "Platform does not support CPUID. Aborting!\n");

  l4_umword_t ax, bx, cx, dx;
  l4util_cpu_cpuid(0, &ax, &bx, &cx, &dx);

  if (bx == 0x756e6547 && cx == 0x6c65746e && dx == 0x49656e69)
    return Vm_state::Type::Vmx;
  // AuthenticAMD
  else if (bx == 0x68747541 && cx == 0x444d4163 && dx == 0x69746e65)
    {
      warn().printf(">>> CAUTION: Support for AMD SVM is experimental, use at your own risk! <<<\n");

      // Check if the SVM features we need are present.
      l4util_cpu_cpuid(0x8000000a, &ax, &bx, &cx, &dx);

      if (!(dx & Svm_state::Cpuid_svm_feature_nrips))
        L4Re::throw_error(-L4_ENOSYS,
                          "SVM does not support next_rip save. Aborting!\n");

      // It should be safe to assume that the decode assists feature is
      // present, since all modern AMD CPUs (starting with Bulldozer)
      // implement it. However, QEMU or rather KVM-based nested virtualization
      // does not report that the feature is present (see svm_set_cpu_caps()),
      // but still provides decode assist information, e.g. for writes to CR0.
      if (!(dx & Svm_state::Cpuid_svm_feature_decode_assists))
        warn().printf("Platform does not support SVM decode assists (misreported on QEMU).\n");

      return Vm_state::Type::Svm;
    }
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
      opcode = get_pt_walker()->walk(vms->cr3(), vms->ip());
    }
  catch (L4::Runtime_error &e)
    {
      warn().printf("[%3u] Could not determine opcode for MMIO access. Page table "
                    "walking failed for IP 0x%lx and reports: %s\n",
                    get_vcpu_id(), vms->ip(), e.extra_str());
      return m;
    }

  // amd64: vcpu regs == exc_regs
  l4_exc_regs_t *reg = reinterpret_cast<l4_exc_regs_t *>(&_s->r);
  using namespace L4mad;
  unsigned char *inst_buf = reinterpret_cast<unsigned char *>(opcode);
  // TODO: Limit inst_buf_len to size until the next non-contiguous page
  //       boundary if it is < Decoder::Max_instruction_len.
  unsigned inst_buf_len = Decoder::Max_instruction_len;
  Decoder decoder(reg, vms->ip(), inst_buf, inst_buf_len);

  bool decoded = false;
  Op op;
  Desc tgt, src;
  switch (decoder.decode(&op, &tgt, &src))
    {
    case Decoder::Result::Success: decoded = true; break;
    case Decoder::Result::Unsupported: break;
    case Decoder::Result::Invalid:
      // TODO: If size of instruction buffer is < Decoder::Max_instruction_len,
      //       because instruction lies on a non-contiguous page boundary,
      //       use a temporary buffer to hold instruction bytes from both pages
      //       and retry decoding from that.
      break;
    }

  if (!decoded)
    {
      unsigned char const *text = reinterpret_cast<unsigned char *>(opcode);
      Dbg().printf("[%3u] Decoding failed at 0x%lx: %02x %02x %02x %02x %02x "
                   "%02x %02x <%02x> %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   get_vcpu_id(), vms->ip(),
                   text[-7], text[-6], text[-5], text[-4], text[-3],
                   text[-2], text[-1], text[0], text[1], text[2], text[3],
                   text[4], text[5], text[6], text[7], text[8]);
      return m;
    }

  if (0)
    decoder.print_insn_info(op, tgt, src);

  m.width = op.access_width;

  if (tgt.dtype != L4mad::Desc_reg && tgt.dtype != L4mad::Desc_mem)
    {
      Dbg().printf("[%3u] tgt type invalid %i\n", get_vcpu_id(), tgt.dtype);
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
      switch (src.dtype)
        {
        case L4mad::Desc_reg:
          // src.val is the register number in MAD order; which is inverse to
          // register order in l4_vcpu_regs_t.
          m.value = *decode_reg_ptr(src.val) >> src.shift;
          break;
        case L4mad::Desc_imm:
          m.value = src.val;
          break;
        default:
          assert(false);
          m.value = 0;
          break;
        }
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

void
Vcpu_ptr::reset(bool protected_mode)
{
  vm_state()->init_state();

  // If Uvmm is to boot a Linux kernel directly, it will do so in protected
  // mode as is required in Linux' boot protocol. Otherwise the Boot and
  // Application Processors are expected to come up in Real Mode.
  if (protected_mode)
    vm_state()->setup_linux_protected_mode(_s->r.ip);
  else
    vm_state()->setup_real_mode(_s->r.ip);

  Guest::get_instance()->run_vm(*this);
}

void
Vcpu_ptr::hot_reset()
{
  // assumption: reset while we already went through the normal reset once.
  // intention: Do not call Guest::run_vm() again.

  vm_state()->init_state();
  vm_state()->setup_real_mode(_s->r.ip);
}

} // namespace Vmm
