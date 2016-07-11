/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/vbus/vbus>
#include <l4/l4virtio/l4virtio>

#include "debug.h"
#include "generic_guest.h"
#include "core_ic.h"
#include "vcpu.h"
#include "irq.h"
#include "vmprint.h"
#include "mips_instructions.h"

namespace Vmm {

class Guest : public Generic_guest
{
  enum Handler_return_codes { Jump_instr = 1 };

  enum Hypcall_code
  {
    Hypcall_base     = 0x160,
    Hypcall_outchar  = Hypcall_base + 0,
  };

public:
  enum { Default_rambase = 0 };

  Guest(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base);
  cxx::Ref_ptr<Gic::Mips_core_ic> core_ic() const  { return _core_ic; }

  void update_device_tree(char const *cmd_line);

  L4virtio::Ptr<void> load_linux_kernel(char const *kernel, l4_addr_t *entry);

  void prepare_linux_run(Cpu vcpu, l4_addr_t entry, char const *kernel,
                         char const *cmd_line);

  void run(Cpu vcpu);

  int dispatch_hypcall(Hypcall_code hypcall_code, Cpu &vcpu);
  void handle_entry(Cpu vcpu);

  void show_state_registers(FILE *) override;
  void show_state_interrupts(FILE *) override;

  static Guest *create_instance(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base);

private:
  int handle_gpsi_mfc0(Cpu vcpu, Mips::Instruction insn)
  {
    l4_umword_t *val = &(vcpu->r.r[insn.rt()]);
    unsigned reg = (insn.rd() << 3) | (insn.func() & 0x7);

    if (0)
      Dbg().printf("MFC0 for 0x%x in register %d (0x%lx)\n",
                   reg, (unsigned) insn.rt(), *val);

    switch (reg)
      {
      case L4_VM_CP0_PROC_ID: *val = _proc_id; break;
      case L4_VM_CP0_SRS_CTL: *val = 0; break;
      case L4_VM_CP0_CMGCR_BASE: // virtual CM not supported
      case L4_VM_CP0_MAAR_0:
      case L4_VM_CP0_MAAR_1:
      case L4_VM_CP0_ERR_CTL:
      case L4_VM_CP0_CONFIG_6:
      case L4_VM_CP0_CONFIG_7:
        *val = 0; break;
      default: return -L4_ENOSYS;
      }

    return Jump_instr;
  }

  int handle_gpsi_mtc0(Cpu vcpu, Mips::Instruction insn)
  {
    (void) vcpu;
    unsigned reg = (insn.rd() << 3) | (insn.func() & 0x7);

    if (0)
    Dbg().printf("MTC0 for 0x%x in register %u \n", reg, (unsigned) insn.rt());

    switch (reg)
      {
      case L4_VM_CP0_CONFIG_0:
      case L4_VM_CP0_CONFIG_1:
      case L4_VM_CP0_CONFIG_2:
      case L4_VM_CP0_CONFIG_3:
      case L4_VM_CP0_CONFIG_4:
      case L4_VM_CP0_CONFIG_5:
      case L4_VM_CP0_CONFIG_6:
      case L4_VM_CP0_CONFIG_7:
        return Jump_instr; // XXX config registers are read-only atm
      case L4_VM_CP0_MAAR_0:
      case L4_VM_CP0_MAAR_1:
      case L4_VM_CP0_ERR_CTL:
        return Jump_instr; // XXX MAAR and parity are not supported
      }

    return -L4_EINVAL;
  }

  int handle_software_field_change(Cpu vcpu, Mips::Instruction insn)
  {
    l4_umword_t val = vcpu->r.r[insn.rt()];
    unsigned reg = (insn.rd() << 3) | (insn.func() & 0x7);
    auto *s = vcpu.state();

    Dbg().printf("MTC0(soft) for 0x%x in register %d (0x%lx) \n",
                 reg, (unsigned) insn.rt(), val);

    switch (reg)
      {
      case L4_VM_CP0_STATUS:
        s->g_status = val;
        s->set_modified(L4_VM_MOD_STATUS);
        return Jump_instr;

      case L4_VM_CP0_CAUSE:
        enum { Cause_mask = 0x8c00ff00UL };
        s->get_state(L4_VM_MOD_CAUSE);
        s->g_cause &= ~Cause_mask;
        s->g_cause |= val & Cause_mask;
        s->set_modified(L4_VM_MOD_CAUSE);
        return Jump_instr;
      }

    return -L4_EINVAL;
  }

  int handle_wait(Cpu vcpu, l4_utcb_t *utcb)
  {
    l4_timeout_t to = L4_IPC_NEVER;
    auto *s = vcpu.state();

    if (s->g_status & 1) // interrupts enabled
      {
        l4_uint32_t kcnt;
        asm volatile("rdhwr\t%0, $2" : "=r"(kcnt)); // timer counter

        s->update_state(L4_VM_MOD_CAUSE | L4_VM_MOD_COMPARE);

        if (s->g_cause & (1UL << 30))
          return Jump_instr; // there was a timer interrupt

        auto *kip = l4re_kip();
        l4_uint32_t gcnt = kcnt + (l4_uint32_t) s->guest_timer_offset;
        l4_uint32_t diff;
        if (gcnt < s->g_compare)
          diff = s->g_compare - gcnt;
        else
          diff = (0xffffffff - gcnt) + s->g_compare;
        diff /= (kip->frequency_cpu / 1000);

        l4_rcv_timeout(l4_timeout_abs_u(l4_kip_clock(kip) + diff, 8, utcb), &to);
      }

    wait_for_ipc(utcb, to);

    return Jump_instr;
  }

  Guest_print_buffer _hypcall_print;
  cxx::Ref_ptr<Gic::Mips_core_ic> _core_ic;
  l4_umword_t _proc_id;
};


} // namespace
