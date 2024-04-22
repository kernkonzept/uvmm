/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *            Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <sys/asm.h>

#include <l4/util/util.h>

#include "cpu_dev.h"
#include "guest.h"
#include "riscv_arch.h"

namespace Vmm
{

Cpu_dev::Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *node)
: Generic_cpu_dev(idx, phys_id)
{
  char const *prop_isa_str = node ? node->get_prop<char>("riscv,isa", nullptr)
                                  : nullptr;
  if (!prop_isa_str)
    return;

  std::string isa_str = prop_isa_str;
  bool has_ext_sstc = l4_kip_has_isa_ext(l4re_kip(), L4_riscv_isa_ext_sstc);
  if (has_ext_sstc && isa_str.find("_sstc") == std::string::npos)
    {
      // Indicate in the device tree that the SSTC extension is available.
      isa_str += "_sstc";
      node->setprop_string("riscv,isa", isa_str.c_str());
    }
}

bool
Cpu_dev::start_vcpu()
{
  if (online_state() != Cpu_state::On_pending)
    {
      // Should we convert this to an assert()?
      Err().printf("%s: CPU%d not in On_pending state", __func__, _phys_cpu_id);
      return false;
    }

    Dbg(Dbg::Cpu, Dbg::Info)
      .printf("Initiating cpu startup @ 0x%lx\n", _vcpu->r.ip);

    if (_vcpu->entry_sp && !restart_vcpu())
      {
        mark_off();
        return false;
      }
    else
      reschedule();

    return true;
}

void L4_NORETURN
Cpu_dev::stop_vcpu()
{
  mark_off();
  while (online_state() != Cpu_state::On_prepared)
    _vcpu.wait_for_ipc(l4_utcb(), L4_IPC_NEVER);

  reset();
}

bool
Cpu_dev::restart_vcpu()
{
  assert(_vcpu->entry_sp);

  mark_on_prepared();

  l4_msgtag_t res = _restart_event.obj_cap()->trigger();
  if (!l4_msgtag_has_error(res))
    return true;

  Err().printf("Error waking Cpu%d: %lx\n", _vcpu.get_vcpu_id(), l4_error(res));
  return false;
}

void
Cpu_dev::powerup_cpu()
{
  Generic_cpu_dev::powerup_cpu();

  // Now the vCPU thread exists and the IPC registry is setup.

  auto *registry = vcpu().get_ipc_registry();
  L4Re::chkcap(registry->register_irq_obj(&_restart_event),
               "Cannot register CPU restart event");

  _stop_irq.arm(registry);
}

void
Cpu_dev::reset()
{
  using namespace Riscv;

  // set thread local cpu id
  vmm_current_cpu_id = _vcpu.get_vcpu_id();

  _vcpu->entry_ip = reinterpret_cast<l4_umword_t>(&Guest::vcpu_entry);

  if (!_vcpu->entry_sp)
    {
      l4_umword_t sp;
      asm volatile ("mv %0, sp" : "=r" (sp));
      _vcpu->entry_sp = sp & ~0xful;
    }

  _vcpu->saved_state =   L4_VCPU_F_FPU_ENABLED
                       | L4_VCPU_F_USER_MODE
                       | L4_VCPU_F_IRQ
                       | L4_VCPU_F_PAGE_FAULTS
                       | L4_VCPU_F_EXCEPTIONS;

  _vcpu->r.hstatus = L4_vm_hstatus_spvp | L4_vm_hstatus_vtw;
#if __riscv_xlen == 64
  _vcpu->r.hstatus |= static_cast<l4_umword_t>(L4_vm_hstatus_vsxl_64)
                      << L4_vm_hstatus_vsxl_shift;
#endif

  auto *vm_state = _vcpu.vm_state();
  vm_state->hedeleg =   1 << Exc_inst_misaligned
                      | 1 << Exc_inst_access
                      | 1 << Exc_illegal_inst
                      | 1 << Exc_breakpoint
                      | 1 << Exc_load_acesss
                      | 1 << Exc_store_acesss
                      | 1 << Exc_ecall
                      | 1 << Exc_inst_page_fault
                      | 1 << Exc_load_page_fault
                      | 1 << Exc_store_page_fault;
  vm_state->hideleg =   1 << (Int_virtual_supervisor_software & ~Msb)
                      | 1 << (Int_virtual_supervisor_timer & ~Msb)
                      | 1 << (Int_virtual_supervisor_external & ~Msb);

  vm_state->hvip = 0;
  vm_state->hip = 0;
  vm_state->hie = 0;

  vm_state->htimedelta = 0;

  vm_state->htval = 0;
  vm_state->htinst = 0;

  Dbg(Dbg::Core, Dbg::Info)
    .printf("Starting vcpu %d @ 0x%lx (handler @ %lx with stack @ %lx)\n",
            _vcpu.get_vcpu_id(), _vcpu->r.ip, _vcpu->entry_ip, _vcpu->entry_sp);

  mark_on();

  L4::Cap<L4::Thread> self;
  auto e = l4_error(self->vcpu_resume_commit(self->vcpu_resume_start()));

  Err().printf("VMM exited with %ld\n", e);
  stop_vcpu();

  // Failed to take vCPU offline. Should not happend but play safe.
  l4_sleep_forever();
}

} // namespace
