/*
 * Copyright (C) 2020-2024 Kernkonzept GmbH.
 * Author(s): Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/cxx/static_container>

#include "binary_loader.h"
#include "guest.h"
#include "riscv_arch.h"

namespace Vmm {

// The singleton instance of the VMM.
static cxx::Static_container<Vmm::Guest> guest;

__thread unsigned vmm_current_cpu_id;

Guest *
Guest::create_instance()
{
  guest.construct();
  return guest;
}

Guest::Guest()
: _sbi(Sbi::create_instance(this))
{
  _has_vstimecmp = l4_kip_has_isa_ext(l4re_kip(), L4_riscv_isa_ext_sstc);
}

void
Guest::setup_device_tree(Vdev::Device_tree dt)
{
  // Provide frequency of platform timer in DTS
  auto node = dt.path_offset("/cpus");
  node.setprop_u32("timebase-frequency",
                   l4re_kip()->platform_info.arch.timebase_frequency);
}

l4_addr_t
Guest::load_binary(Vm_ram *ram, char const *binary, Ram_free_list *free_list)
{
  l4_addr_t entry;

  Boot::Binary_loader_factory bf;
  bf.load(binary, ram, free_list, &entry);

  return entry;
}

void
Guest::prepare_platform(Vdev::Device_lookup *devs)
{
  _cpus = devs->cpus();
  _ram = devs->ram();
}

void
Guest::prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const *, char const *, l4_addr_t dt_boot_addr)
{
  Vcpu_ptr vcpu = devs->cpus()->vcpu(0);

  // Arguments as provided by firmware (e.g. OpenSBI)
  // a0: Hart ID
  vcpu->r.a0 = vcpu.get_vcpu_id();
  // a1: Flattened Device Tree
  vcpu->r.a1 = dt_boot_addr;

  vcpu->r.ip = entry;
}

void
Guest::run(cxx::Ref_ptr<Cpu_dev_array> const &cpus)
{
  if (!_plic)
    {
       Err().printf("No PLIC found.\n");
       L4Re::throw_error(-L4_ENODEV, "No PLIC found.");
    }

  Vdev::Virtual_timer::init_frequency();

  for (auto cpu: *cpus.get())
    {
      if (!cpu)
        continue;

      auto vcpu = cpu->vcpu();
      auto vcpu_id = vcpu.get_vcpu_id();

      vcpu->user_task = _task.cap();
      cpu->powerup_cpu();
      info().printf("Powered up cpu%d [%p]\n", vcpu_id, cpu.get());

      if (vcpu_id >= _vcpu_ics.size())
        _vcpu_ics.resize(vcpu_id + 1);

      _vcpu_ics[vcpu_id] = Vdev::make_device<Gic::Vcpu_ic>(vcpu, registry());
      _vcpu_ics[vcpu_id]->attach_cpu_thread(cpu->thread_cap());
      cpu->set_vcpu_ic(_vcpu_ics[vcpu_id]);

      if (!_has_vstimecmp)
        {
          if (vcpu_id >= _timers.size())
            _timers.resize(vcpu_id + 1);

          _timers[vcpu_id] = Vdev::make_device<Vdev::Virtual_timer>(
            vcpu, cpu->thread_cap(), _vcpu_ics[vcpu_id]);
          _timers[vcpu_id]->start_timer_thread(cpu->get_phys_cpu_id());
        }

      _plic->setup_target(vcpu, _vcpu_ics[vcpu_id]);
    }

  cpus->cpu(0)->mark_on_pending();
  cpus->cpu(0)->startup();
}

void
Guest::sync_all_other_cores_off() const
{
  bool all_stop = true;
  do
    {
      all_stop = true;
      for (auto cpu : *_cpus.get())
        {
          if (cpu && cpu->vcpu().get_vcpu_id() == vmm_current_cpu_id)
            continue;

          if (cpu && cpu->online())
            {
              all_stop = false;
              break;
            }
        }
    } while (!all_stop);
};

void L4_NORETURN
Guest::halt_vm(Vcpu_ptr current_vcpu)
{
  stop_cpus();
  sync_all_other_cores_off();
  Generic_guest::halt_vm(current_vcpu);
}

void L4_NORETURN
Guest::shutdown(int val)
{
  stop_cpus();
  Generic_guest::shutdown(val);
}

void
Guest::stop_cpus()
{
  // Exit all vCPU threads into the vmm and stop the vCPUs.
  for (auto cpu: *_cpus.get())
    {
      if (   cpu && cpu->online()
          && cpu->vcpu().get_vcpu_id() != vmm_current_cpu_id)
        cpu->send_stop_event();
    }
}

void
Guest::wfi(Vcpu_ptr vcpu)
{
  bool pending_irq = vcpu.has_pending_irq();
  // If Sstc extension is used there is no timer-thread to wake us up, so we
  // have to set up a receive timeout according to the next timer event the
  // guest configured in vstimecmp.
  l4_timeout_t wait_timeout = L4_IPC_NEVER;
  if (!pending_irq && _has_vstimecmp && (vcpu.vm_state()->hie & L4_vm_hvip_vstip))
    pending_irq = !Vdev::Virtual_timer::setup_event_rcv_timeout(
                    l4_utcb(), &wait_timeout, vcpu.vm_state()->vstimecmp);

  if (!pending_irq)
    vcpu.wait_for_ipc(l4_utcb(), wait_timeout);
}

void
Guest::handle_entry(Vcpu_ptr vcpu)
{
  switch (vcpu->r.cause)
    {
      case Riscv::Exc_hcall:
        handle_ecall(vcpu);
        break;
      case Riscv::Exc_guest_inst_page_fault:
      case Riscv::Exc_guest_load_page_fault:
      case Riscv::Exc_guest_store_page_fault:
        handle_page_fault(vcpu);
        break;
      case Riscv::Exc_virtual_inst:
        handle_virtual_inst(vcpu);
        break;
      case Riscv::L4_ipc_upcall:
        handle_ipc_upcall(vcpu);
        break;
      case Riscv::L4_exregs_exception:
        handle_exregs_exception(vcpu);
        break;
      case Riscv::Exc_illegal_inst:
        // Fiasco prevents delegation of illegal instruction exception if lazy
        // FPU switching is enabled.
        redirect_trap(vcpu);
        break;
      default:
        {
          auto *vm_state = vcpu.vm_state();
          Err().printf("[%3u] Unexpected VMM entry!\n", vcpu.get_vcpu_id());
          Err().printf("=== l4 vCPU state ===\n"
                        "pc: 0x%lx\n"
                        "ra: 0x%lx\n"
                        "cause: 0x%lx\n"
                        "pfa: 0x%lx\n"
                        "state: 0x%x\n"
                        "saved_state: 0x%x\n"
                        "=== extended vCPU state ===\n"
                        "hstatus: 0x%lx\n"
                        "htval: 0x%lx\n"
                        "htinst: 0x%lx\n",
                        vcpu->r.ip, vcpu->r.ra, vcpu->r.cause, vcpu->r.pfa,
                        vcpu->state, vcpu->saved_state,
                        vcpu->r.hstatus, vm_state->htval, vm_state->htinst);

          halt_vm(vcpu);
        }
    }

  vcpu.process_pending_ipc(l4_utcb());
}

void
Guest::handle_ipc_upcall(Vcpu_ptr vcpu)
{
  vcpu.handle_ipc(vcpu->i.tag, vcpu->i.label, l4_utcb());
}

void
Guest::handle_exregs_exception(Vcpu_ptr vcpu)
{
  warn().printf("[%3u] Ex_regs exception exit received. Nothing to do!\n",
                vcpu.get_vcpu_id());
}

void
Guest::handle_ecall(Vcpu_ptr vcpu)
{
  if(!_sbi->handle(vcpu))
    halt_vm(vcpu);

  // Advance ip to continue execution after ecall instruction
  vcpu.jump_system_instruction();
}

void
Guest::handle_page_fault(Vcpu_ptr vcpu)
{
  auto *vm_state = vcpu.vm_state();

  assert(vcpu->r.hstatus & L4_vm_hstatus_gva);
  // htval is either zero or the guest physical address shifted to
  // the right by 2 bits, to allow addresses wider than the current XLEN.
  // The least-significant two bits can be taken from stval.
  l4_addr_t gpa_addr = (vm_state->htval << 2) + (vcpu->r.tval & 0b11);

  if (vcpu->r.cause == Riscv::Exc_guest_inst_page_fault)
    {
      Err().printf(
        "cannot handle VM instruction page fault @ 0x%lx "
        "ip=0x%lx ra=0x%lx cause=0x%lx tval=0x%lx htval=0x%lx\n",
        gpa_addr, vcpu->r.ip, vcpu->r.ra, vcpu->r.cause,
        vcpu->r.tval, vcpu.vm_state()->htval);
      guest->halt_vm(vcpu);
    }

  fetch_guest_inst(vcpu);

  switch (handle_mmio(gpa_addr, vcpu))
    {
    case Retry: break;
    case Jump_instr: vcpu.jump_trap_instruction(); break;
    default:
      Err().printf(
        "cannot handle VM memory access @ 0x%lx "
        "ip=0x%lx ra=0x%lx cause=0x%lx tval=0x%lx htval=0x%lx\n",
        gpa_addr, vcpu->r.ip, vcpu->r.ra, vcpu->r.cause,
        vcpu->r.tval, vcpu.vm_state()->htval);
      guest->halt_vm(vcpu);
      break;
    }
}

void
Guest::handle_virtual_inst(Vcpu_ptr vcpu)
{
  fetch_guest_inst(vcpu);
  Riscv::Instruction inst(vcpu.vm_state()->htinst);
  if (inst.is_wfi())
    {
      // Resume with instruction following wfi
      vcpu.jump_system_instruction();
      wfi(vcpu);
    }
  else
    {
      Err().printf("Unsupported virtual instruction @ 0x%lx: 0x%x\n",
                   vcpu->r.pc, inst.inst);
      guest->halt_vm(vcpu);
    }
}

void
Guest::vcpu_entry(l4_vcpu_state_t *vcpu)
{
  Vmm::Vcpu_ptr c(vcpu);
  if (!(vcpu->saved_state & L4_VCPU_F_USER_MODE)
      && vcpu->r.cause != Riscv::L4_exregs_exception)
    {
      Err().printf("Exception in entry handler. Halting. "
                   "ip=0x%lx cause=0x%lx pfa=0x%lx\n",
                   vcpu->r.ip, vcpu->r.cause, vcpu->r.pfa);
      guest->halt_vm(c);
    }

  guest->handle_entry(c);

  L4::Cap<L4::Thread> self;
  auto e = l4_error(self->vcpu_resume_commit(self->vcpu_resume_start()));

  Err().printf("VM resume failed with %ld\n", e);
  guest->halt_vm(c);
}

/**
 * Lookup CPU for untrusted vCPU ID, i.e. it might be provided by the guest, and
 * thus might not refer to an existing CPU.
 */
Cpu_dev *
Guest::lookup_cpu(l4_umword_t vcpu_id) const
{
  if (_cpus->vcpu_exists(vcpu_id))
    return _cpus->cpu(vcpu_id).get();

  return nullptr;
}

/**
 * Fetches and decodes the instruction at the current instruction pointer if
 * necessary.
 *
 * To emulate MMIO accesses and handle virtual instruction exceptions, we need
 * to decode the faulting instruction. The htinst register might contain
 * information about this instruction, but this is an optional feature. In case
 * htinst does not contain information, we have to fetch the instruction by
 * manually reading from guest memory at the current instruction pointer.
 */
void
Guest::fetch_guest_inst(Vcpu_ptr vcpu)
{
  auto vm_state = vcpu.vm_state();

  // Hardware did not provide trapped instruction in htinst, try to read the
  // instruction from memory.
  if (vm_state->htinst == 0)
    {
      bool failed = false;
      l4_uint32_t inst = read_guest_mem_inst(vcpu->r.pc, vm_state, &failed);
      if (!failed)
        {
          if (!Riscv::is_compressed_inst(inst))
            {
              // Not a compressed instruction, so read the remaining 16 bit.
              inst |= read_guest_mem_inst(vcpu->r.pc + 2, vm_state, &failed) << 16;
            }
          else
            {
              // Transform compressed instruction according to the RISC-V privileged spec.
              Riscv::C_instruction c_inst(inst);
              inst = c_inst.transformed().inst;
              trace().printf(
                "Transformed compressed instruction @ 0x%lx: 0x%x -> 0x%x\n",
                vcpu->r.pc, c_inst.inst, inst);
            }
        }

      if (failed)
        {
          warn().printf(
            "Failed to read guest instruction @ 0x%lx\n", vcpu->r.pc);
          return;
        }

      vm_state->htinst = inst;
    }
}

/**
 * Read the instruction at the given guest virtual address.
 *
 * Reads the instruction with a hypervisor virtual-machine load instruction,
 * which allows to access guest memory with the same address translation
 * conditions that would apply for the guest, so fortunately no need to
 * manually walk the guest page tables.
 */
l4_uint16_t
Guest::read_guest_mem_inst(l4_addr_t guest_virt_addr,
                           l4_vm_state_t *vm_state, bool *failed)
{
  // Fiasco catches failed HLV/HLVX/HSV instructions,
  // skips them and sets vm_state->hlsi_failed to true.
  vm_state->hlsi_failed = false;

  register l4_umword_t tmp asm("a0") = guest_virt_addr;
  /*
   * HLVX.HU a0, (a0)
   * 0110010 00011 01010 100 01010 1110011
   */
  asm volatile (".word 0x64354573" : "+r" (tmp) : : "memory");

  *failed = vm_state->hlsi_failed;
  return tmp;
}

void
Guest::redirect_trap(Vcpu_ptr vcpu)
{
  auto *vm_state = vcpu.vm_state();

  // Record privilege level before trap.
  if (vcpu->r.hstatus & Riscv::Hstatus_spvp)
    vm_state->vsstatus |= Riscv::Sstatus_spp;
  else
    vm_state->vsstatus &= ~Riscv::Sstatus_spp;

  // Disable interrupts on trap.
  if (vm_state->vsstatus & Riscv::Sstatus_sie)
    {
      vm_state->vsstatus |= Riscv::Sstatus_spie;
      vm_state->vsstatus &= ~Riscv::Sstatus_sie;
    }
  else
    vm_state->vsstatus &= ~Riscv::Sstatus_spie;

  // Setup registers with trap info.
  vm_state->vsepc = vcpu->r.pc;
  vm_state->vscause = vcpu->r.cause;
  vm_state->vstval = vcpu->r.tval;

  // Jump to guest exception vector.
  vcpu->r.pc = vm_state->vstvec & ~Riscv::Stvec_mode_mask;
}

} // namespace
