/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2015-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */
#include <l4/cxx/unique_ptr>
#include <l4/cxx/ref_ptr>
#include <l4/re/error_helper>
#include <l4/vbus/vbus>
#include <l4/sys/debugger.h>

#include "binary_loader.h"
#include "device_factory.h"
#include "guest.h"
#include "guest_subarch.h"
#include "irq.h"
#include "irq_dt.h"
#include "sys_reg.h"
#include "virt_bus.h"

#include "vm_print.h"

static cxx::unique_ptr<Vmm::Guest> guest;

__thread unsigned vmm_current_cpu_id;

typedef void (*Entry)(Vmm::Vcpu_ptr vcpu);

namespace Vmm {

namespace {

using namespace Arm;

struct DCCSR : Sys_reg_ro
{
  l4_uint32_t flip = 0;

  l4_uint64_t read(Vmm::Vcpu_ptr, Key) override
  {
    // printascii in Linux is doing busyuart which wants to see a
    // busy flag to quit its loop while waituart does not want to
    // see a busy flag; this little trick makes it work
    flip ^= 1 << 29;
    return flip;
  }
};

struct DBGDTRxX : Sys_reg_const<0>
{
  void write(Vmm::Vcpu_ptr, Key, l4_uint64_t v) override
  {
    putchar(v);
  }
};

// Helper for logging read/write accesses to groups of known system registers
// where the 'n' value is encoded by the 'CRm'.
// Write accesses are not performed. Read accesses return 0.
struct Sys_reg_log_n : Sys_reg
{
  Sys_reg_log_n(char const *name)
  : name(name)
  {}

  void write(Vmm::Vcpu_ptr vcpu, Key k, l4_uint64_t v) override
  {
    Dbg(Dbg::Core, Dbg::Info)
      .printf("%08lx: msr %s%d_EL1 = %08llx (ignored)\n",
              vcpu->r.ip, name, static_cast<unsigned>(k.crm()), v);
  }

  l4_uint64_t read(Vmm::Vcpu_ptr vcpu, Key k) override
  {
    Dbg(Dbg::Core, Dbg::Info)
      .printf("%08lx: mrs %s%d_EL1 (read 0)\n",
              vcpu->r.ip, name, static_cast<unsigned>(k.crm()));
    return 0;
  }

  char const *name;
};

// Helper for logging read/write accesses to dedicated known system registers.
// Write accesses are not performed. Read accesses return 0.
struct Sys_reg_log : Sys_reg
{
  Sys_reg_log(char const *name)
  : name(name)
  {}

  void write(Vmm::Vcpu_ptr vcpu, Key, l4_uint64_t v) override
  {
    Dbg(Dbg::Core, Dbg::Info)
      .printf("%08lx: msr %s = %08llx (ignored)\n", vcpu->r.ip, name, v);
  }

  l4_uint64_t read(Vmm::Vcpu_ptr vcpu, Key) override
  {
    Dbg(Dbg::Core, Dbg::Info)
      .printf("%08lx: mrs %s (read 0)\n", vcpu->r.ip, name);
    return 0;
  }

  char const *name;
};

}

Guest::Guest()
: _gic(Gic::Dist_if::create_dist(l4_vcpu_e_info(*Cpu_dev::main_vcpu())->gic_version,
                                 31))
{
  cxx::Ref_ptr<Sys_reg> r = cxx::make_ref_obj<DCCSR>();
  add_sys_reg_aarch32(14, 0, 0, 1, 0, r); // DBGDSCRint
  add_sys_reg_aarch64( 2, 3, 0, 1, 0, r);
  // MDSCR_EL1 (we can map this to DBGSCRint as long as we only implement bit 29..30
  add_sys_reg_aarch64( 2, 0, 0, 2, 2, r);

  // DBGIDR
  add_sys_reg_aarch32(14, 0, 0, 0, 0, cxx::make_ref_obj<Sys_reg_const<0>>());

  r = cxx::make_ref_obj<DBGDTRxX>();
  add_sys_reg_aarch32(14, 0, 0, 5, 0, r);
  add_sys_reg_aarch64( 2, 3, 0, 5, 0, r);

  // Log miscellaneous debug / non-debug registers
  r = cxx::make_ref_obj<Sys_reg_log_n>("DBGBVR");
  for (unsigned i = 0; i < 16; ++i)
    add_sys_reg_aarch64(2, 0, 0, i, 4, r);

  r = cxx::make_ref_obj<Sys_reg_log_n>("DBGBCR");
  for (unsigned i = 0; i < 16; ++i)
    add_sys_reg_aarch64(2, 0, 0, i, 5, r);

  r = cxx::make_ref_obj<Sys_reg_log_n>("DBGWVR");
  for (unsigned i = 0; i < 16; ++i)
    add_sys_reg_aarch64(2, 0, 0, i, 6, r);

  r = cxx::make_ref_obj<Sys_reg_log_n>("DBGWCR");
  for (unsigned i = 0; i < 16; ++i)
    add_sys_reg_aarch64(2, 0, 0, i, 7, r);

  r = cxx::make_ref_obj<Sys_reg_log>("OSLAR_EL1");
  add_sys_reg_aarch64(2, 0, 1, 0, 4, r);

  r = cxx::make_ref_obj<Sys_reg_log>("OSDLR_EL1");
  add_sys_reg_aarch64(2, 0, 1, 3, 4, r);

  r = cxx::make_ref_obj<Sys_reg_log>("PMUSERENR_EL0");
  add_sys_reg_aarch64(3, 3, 9, 14, 0, r);
}

Guest *
Guest::create_instance()
{
  guest = cxx::make_unique<Guest>();
  return guest.get();
}

Guest *
Guest::instance()
{
  return guest.get();
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto gic = devs->vmm()->gic();
    return gic->setup_gic(devs, node);
  }
};

static F f;
static Vdev::Device_type t1 = { "arm,cortex-a9-gic", nullptr, &f };
static Vdev::Device_type t2 = { "arm,cortex-a15-gic", nullptr, &f };
static Vdev::Device_type t3 = { "arm,cortex-a7-gic", nullptr, &f };
static Vdev::Device_type t4 = { "arm,gic-400", nullptr, &f };
static Vdev::Device_type t5 = { "arm,gic-v3", nullptr, &f };

struct F_timer : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Device_lookup *devs,
                                    Vdev::Dt_node const &node) override
  {
    Vdev::Irq_dt_iterator it(devs, node);

    // skip the first two interrupts
    for (int i = 0; i < 3; ++i)
      L4Re::chksys(it.next(devs), "Parsing timer interrupt");

    if (!it.ic_is_virt())
      L4Re::chksys(-L4_EINVAL, "Timer not connected to virtual interrupt controller");

    auto timer = Vdev::make_device<Vdev::Core_timer>(it.ic(), it.irq(), node);

    devs->vmm()->set_timer(timer);
    return timer;
  }
};

static F_timer ftimer;
static Vdev::Device_type tt1 = { "arm,armv7-timer", nullptr, &ftimer };
static Vdev::Device_type tt2 = { "arm,armv8-timer", nullptr, &ftimer };

} // namespace


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

void
Guest::check_guest_constraints(l4_addr_t base) const
{
  Dbg warn(Dbg::Mmio, Dbg::Warn, "ram");

  if (_guest_64bit)
    {
      if (base & ((1UL << 21) - 1))
        warn.printf(
          "\033[01;31mWARNING: Guest memory not 2MB aligned!\033[m\n"
          "       If you run a 64bit-Linux as a guest,\n"
          "       Linux will likely fail to boot as it expects\n"
          "       a 2MB alignment of its memory.\n"
          "       Current guest RAM alignment is only 0x%x\n",
          1 << __builtin_ctz(base));

      return;
    }

  if (base & ((1UL << 27) - 1))
    warn.printf(
      "\033[01;31mWARNING: Guest memory not 128MB aligned!\033[m\n"
      "       If you run a 32bit-Linux as a guest,\n"
      "       Linux will likely fail to boot as it assumes\n"
      "       a 128MB alignment of its memory.\n"
      "       Current guest RAM alignment is only 0x%x\n",
      1 << __builtin_ctz(base));

  if (base & ~0xf0000000)
    warn.printf(
      "WARNING: Guest memory not 256MB aligned!\n"
      "       If you run a 32bit-Linux as a guest, you might hit a bug\n"
      "       in the arch/arm/boot/compressed/head.S code\n"
      "       that misses an ISB after code has been relocated.\n"
      "       According to the internet a fix for this issue\n"
      "       is floating around.\n");
}

l4_addr_t
Guest::load_binary(Vm_ram *ram, char const *binary, Ram_free_list *free_list)
{
  l4_addr_t entry;
  Vmm::Guest_addr ram_base = free_list->first_free_address();

  Boot::Binary_loader_factory bf;
  bf.load(binary, ram, free_list, &entry);

  _guest_64bit = bf.is_64bit();

  check_guest_constraints(ram_base.get());

  char const *n = strrchr(binary, '/');
  l4_debugger_set_object_name(_task.get().cap(), n ? n+1 : binary);

  return entry;
}

  /*
   * Prepare a clean vcpu register state before entering the VM
   *
   * Initializes the VCPU register state according to the mode the
   * VCPU is supposed to run in. Registers related to virtualization
   * (control registers, vcpu state registers) are initialized in the
   * context of the thread handling this virtual CPU.
   * We assume that this state is not changed by invoking
   * vcpu_control_ext().
   */
void
Guest::prepare_vcpu_startup(Vcpu_ptr vcpu, l4_addr_t entry) const
{
  if (Guest_64bit_supported && _guest_64bit)
    vcpu->r.flags = Cpu_dev::Flags_default_64;
  else
    {
      vcpu->r.flags = Cpu_dev::Flags_default_32;
      if (entry & 1)
        {
          // set thumb mode, remove thumb bit from address
          vcpu->r.flags |= 1 << 5;
          entry &= ~1;
        }
    }

  vcpu->r.sp    = 0;
  vcpu->r.ip    = entry;
}

void
Guest::prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const * /*kernel*/, char const * /*cmd_line*/,
                          l4_addr_t dt_boot_addr)
{
  Vcpu_ptr vcpu = devs->cpus()->vcpu(0);
  prepare_vcpu_startup(vcpu, entry);

  // Set up the VCPU state as expected by Linux entry
  if (Guest_64bit_supported && _guest_64bit)
    {
      vcpu->r.r[0]  = dt_boot_addr;
      vcpu->r.r[1]  = 0;
      vcpu->r.r[2]  = 0;
    }
  else
    {
      vcpu->r.r[0]  = 0;
      vcpu->r.r[1]  = ~0UL;
      vcpu->r.r[2]  = dt_boot_addr;
    }
  vcpu->r.r[3]  = 0;
}

void
Guest::run(cxx::Ref_ptr<Cpu_dev_array> cpus)
{
  if (!_timer)
    warn().printf("WARNING: No timer found. Your guest will likely not work properly!\n");

  register_vm_handler(Hvc, Vdev::make_device<Vm_print_device>(cpus->size()));

  for (auto cpu: *cpus.get())
    {
      if (!cpu)
        continue;

      auto vcpu = cpu->vcpu();

      vcpu->user_task = _task.cap();
      cpu->powerup_cpu();
      info().printf("Powered up cpu%d [%p]\n", vcpu.get_vcpu_id(),
                    cpu.get());

      _gic->setup_cpu(vcpu);
    }
  cpus->cpu(0)->mark_on_pending();
  cpus->cpu(0)->startup();
}

void
Guest::cpu_online(Cpu_dev *cpu)
{
  _gic->cpu_online(cpu->vcpu());
}

void
Guest::cpu_offline(Cpu_dev *cpu)
{
  _gic->cpu_offline(cpu->vcpu());
}

void Guest::stop_cpus()
{
  // Exit all vCPU threads into the vmm and stop the vCPUs.
  for (auto cpu: *_cpus.get())
    {
      if (   cpu && cpu->online()
          && cpu->vcpu().get_vcpu_id() != vmm_current_cpu_id)
        cpu->send_stop_event();
    }
}

l4_msgtag_t
Guest::handle_entry(Vcpu_ptr vcpu)
{
  auto *utcb = l4_utcb();

  vcpu.process_pending_ipc(utcb);
  _gic->schedule_irqs(vmm_current_cpu_id);

  L4::Cap<L4::Thread> myself;
  return myself->vcpu_resume_start(utcb);
}

static void dispatch_vm_call(Vcpu_ptr vcpu)
{
  guest->handle_smccc_call<Guest::Hvc>(vcpu);
}

static void dispatch_smc(Vcpu_ptr vcpu)
{
  guest->handle_smccc_call<Guest::Smc>(vcpu);
}

static void
guest_unknown_fault(Vcpu_ptr vcpu)
{
  // Strip register values if the guest is executed in 32-bit mode.
  l4_umword_t mask = (vcpu->r.flags & 0x10) ? ~0U : ~0UL;
  Err().printf("[%3u] unknown trap: err=%lx ec=0x%x ip=%lx lr=%lx\n",
               vcpu.get_vcpu_id(),
               vcpu->r.err, static_cast<int>(vcpu.hsr().ec()),
               vcpu->r.ip & mask, vcpu.get_lr() & mask);
  if (!guest->inject_undef(vcpu))
    guest->halt_vm(vcpu);
}

static void
guest_memory_fault(Vcpu_ptr vcpu)
{
  switch (guest->handle_mmio(vcpu->r.pfa, vcpu))
    {
    case Retry: break;
    case Jump_instr: vcpu.jump_instruction(); break;
    default:
      {
        // Strip register values if the guest is executed in 32-bit mode.
        l4_umword_t mask = (vcpu->r.flags & 0x10) ? ~0U : ~0UL;
        Err().printf("cannot handle VM memory access @ %lx ip=%lx lr=%lx\n",
                     vcpu->r.pfa & mask, vcpu->r.ip & mask, vcpu.get_lr() & mask);
        guest->halt_vm(vcpu);
        break;
      }
    }
}

bool
Vmm::Guest::inject_abort(l4_addr_t addr, Vcpu_ptr vcpu)
{
  // Inject an instruction abort?
  bool inst = vcpu.hsr().ec() == Hsr::Ec_iabt_low;
  return inject_abort(vcpu, inst, addr);
}

void
Vmm::Guest::wait_for_timer_or_irq(Vcpu_ptr vcpu)
{
  if (_gic->schedule_irqs(vmm_current_cpu_id))
    return;

  l4_timeout_t to = L4_IPC_NEVER;

  auto *utcb = l4_utcb();
  if (_timer
      && (l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_CNTVCTL) & 3) == 1) // timer enabled and not masked
    {
      // calculate the timeout based on the VTIMER values !
      auto cnt = vcpu.cntvct();
      auto cmp = vcpu.cntv_cval();

      if (cmp <= cnt)
        return;

      l4_uint64_t diff = _timer->get_micro_seconds(cmp - cnt);
      if (0)
        printf("diff=%lld\n", diff);
      l4_rcv_timeout(l4_timeout_abs_u(l4_kip_clock(l4re_kip()) + diff, 8, utcb), &to);
    }

  vcpu.wait_for_ipc(utcb, to);
}

void
Vmm::Guest::handle_wfx(Vcpu_ptr vcpu)
{
  vcpu->r.ip += 2 << vcpu.hsr().il();
  if (vcpu.hsr().wfe_trapped()) // WFE
    return;

  wait_for_timer_or_irq(vcpu);
}

static void
guest_wfx(Vcpu_ptr vcpu)
{ guest->handle_wfx(vcpu); }


void
Vmm::Guest::handle_ppi(Vcpu_ptr vcpu)
{
  switch (vcpu.hsr().svc_imm())
    {
    case 0: // VGIC IRQ
      _gic->handle_maintenance_irq(vmm_current_cpu_id);
      break;
    case 1: // VTMR IRQ
      if (_timer)
        _timer->inject();
      break;
    default:
      Err().printf("unknown virtual PPI: %d\n",
                   static_cast<int>(vcpu.hsr().svc_imm()));
      break;
    }
}

static void
guest_ppi(Vcpu_ptr vcpu)
{ guest->handle_ppi(vcpu); }

static void guest_irq(Vcpu_ptr vcpu)
{
  vcpu.handle_ipc(vcpu->i.tag, vcpu->i.label, l4_utcb());
}

template<unsigned CP>
static void guest_mcrr_access_cp(Vcpu_ptr vcpu)
{
  using Vmm::Arm::Sys_reg;
  using Key = Sys_reg::Key;
  auto hsr = vcpu.hsr();

  try
    {
      Key k = Key::cp_r_64(CP, hsr.mcrr_opc1(), hsr.mcr_crm());

      auto r = guest->sys_reg(k);
      if (hsr.mcr_read())
        {
          l4_uint64_t v = r->read(vcpu, k);
          vcpu.set_gpr(hsr.mcr_rt(), v & 0xffffffff);
          vcpu.set_gpr(hsr.mcrr_rt2(), v >> 32);
        }
      else
        {
          l4_uint64_t v
            = (vcpu.get_gpr(hsr.mcr_rt()) & 0xffffffff)
              | (static_cast<l4_uint64_t>(vcpu.get_gpr(hsr.mcrr_rt2())) << 32);

          r->write(vcpu, k, v);
        }

      vcpu.jump_instruction();
    }
  catch (...)
    {
      printf("%08lx: %s p%u, %d, r%d, c%d, c%d, %d (hsr=%08lx)\n",
             vcpu->r.ip, hsr.mcr_read() ? "MRC" : "MCR", CP,
             static_cast<unsigned>(hsr.mcr_opc1()),
             static_cast<unsigned>(hsr.mcr_rt()),
             static_cast<unsigned>(hsr.mcr_crn()),
             static_cast<unsigned>(hsr.mcr_crm()),
             static_cast<unsigned>(hsr.mcr_opc2()),
             static_cast<l4_umword_t>(hsr.raw()));
      vcpu.jump_instruction();
    }
}
template<unsigned CP>
static void guest_mcr_access_cp(Vcpu_ptr vcpu)
{
  using Vmm::Arm::Sys_reg;
  using Key = Sys_reg::Key;
  auto hsr = vcpu.hsr();

  try
    {
      Key k = Key::cp_r(CP, hsr.mcr_opc1(),
                        hsr.mcr_crn(),
                        hsr.mcr_crm(),
                        hsr.mcr_opc2());

      auto r = guest->sys_reg(k);
      if (hsr.mcr_read())
        vcpu.set_gpr(hsr.mcr_rt(), r->read(vcpu, k));
      else
        r->write(vcpu, k, vcpu.get_gpr(hsr.mcr_rt()));

      vcpu.jump_instruction();
    }
  catch (...)
    {
      printf("%08lx: %s p%u, %d, r%d, c%d, c%d, %d (hsr=%08lx)\n",
             vcpu->r.ip, hsr.mcr_read() ? "MRC" : "MCR", CP,
             static_cast<unsigned>(hsr.mcr_opc1()),
             static_cast<unsigned>(hsr.mcr_rt()),
             static_cast<unsigned>(hsr.mcr_crn()),
             static_cast<unsigned>(hsr.mcr_crm()),
             static_cast<unsigned>(hsr.mcr_opc2()),
             static_cast<l4_umword_t>(hsr.raw()));
      vcpu.jump_instruction();
    }
}

static void guest_msr_access(Vcpu_ptr vcpu)
{
  using Vmm::Arm::Sys_reg;
  using Key = Sys_reg::Key;
  auto hsr = vcpu.hsr();

  try
    {
      Key k = Key::sr(hsr.msr_op0(),
                      hsr.msr_op1(),
                      hsr.msr_crn(),
                      hsr.msr_crm(),
                      hsr.msr_op2());

      auto r = guest->sys_reg(k);
      if (hsr.msr_read())
        vcpu.set_gpr(hsr.msr_rt(), r->read(vcpu, k));
      else
        r->write(vcpu, k, vcpu.get_gpr(hsr.msr_rt()));

      vcpu.jump_instruction();
    }
  catch (...)
    {
      if (hsr.msr_read())
        printf("%08lx: mrs r%u, S%u_%u_C%u_C%u_%u (hsr=%08lx)\n",
               vcpu->r.ip, static_cast<unsigned>(hsr.msr_rt()),
               static_cast<unsigned>(hsr.msr_op0()),
               static_cast<unsigned>(hsr.msr_op1()),
               static_cast<unsigned>(hsr.msr_crn()),
               static_cast<unsigned>(hsr.msr_crm()),
               static_cast<unsigned>(hsr.msr_op2()),
               static_cast<l4_umword_t>(hsr.raw()));
      else
        printf("%08lx: msr S%u_%u_C%u_C%u_%u = %08lx (hsr=%08lx)\n",
               vcpu->r.ip,
               static_cast<unsigned>(hsr.msr_op0()),
               static_cast<unsigned>(hsr.msr_op1()),
               static_cast<unsigned>(hsr.msr_crn()),
               static_cast<unsigned>(hsr.msr_crm()),
               static_cast<unsigned>(hsr.msr_op2()),
               vcpu.get_gpr(hsr.msr_rt()),
               static_cast<l4_umword_t>(hsr.raw()));

      vcpu.jump_instruction();
    }
}

static void ex_regs_exception(Vcpu_ptr)
{
  Dbg warn(Dbg::Cpu, Dbg::Warn, "CPU");
  warn.printf("Ex_regs exception exit received. Nothing to do!\n");
}

extern "C" l4_msgtag_t prepare_guest_entry(Vcpu_ptr vcpu);
l4_msgtag_t prepare_guest_entry(Vcpu_ptr vcpu)
{ return guest->handle_entry(vcpu); }

} // namespace

using namespace Vmm;
Entry vcpu_entries[64] =
{
  [0x00] = guest_unknown_fault,
  [0x01] = guest_wfx,
  [0x02] = guest_unknown_fault,
  [0x03] = guest_mcr_access_cp<15>,
  [0x04] = guest_mcrr_access_cp<15>,
  [0x05] = guest_mcr_access_cp<14>,
  [0x06] = guest_unknown_fault,
  [0x07] = guest_unknown_fault,
  [0x08] = guest_unknown_fault,
  [0x09] = guest_unknown_fault,
  [0x0a] = guest_unknown_fault,
  [0x0b] = guest_unknown_fault,
  [0x0c] = guest_mcrr_access_cp<14>,
  [0x0d] = guest_unknown_fault,
  [0x0e] = guest_unknown_fault,
  [0x0f] = guest_unknown_fault,
  [0x10] = guest_unknown_fault,
  [0x11] = guest_unknown_fault,
  [0x12] = dispatch_vm_call,
  [0x13] = dispatch_smc,
  [0x14] = guest_unknown_fault,
  [0x15] = guest_unknown_fault,
  [0x16] = dispatch_vm_call,
  [0x17] = dispatch_smc,
  [0x18] = guest_msr_access,
  [0x19] = guest_unknown_fault,
  [0x1a] = guest_unknown_fault,
  [0x1b] = guest_unknown_fault,
  [0x1c] = guest_unknown_fault,
  [0x1d] = guest_unknown_fault,
  [0x1e] = guest_unknown_fault,
  [0x1f] = guest_unknown_fault,
  [0x20] = guest_memory_fault,
  [0x21] = guest_unknown_fault,
  [0x22] = guest_unknown_fault,
  [0x23] = guest_unknown_fault,
  [0x24] = guest_memory_fault,
  [0x25] = guest_unknown_fault,
  [0x26] = guest_unknown_fault,
  [0x27] = guest_unknown_fault,
  [0x28] = guest_unknown_fault,
  [0x29] = guest_unknown_fault,
  [0x2a] = guest_unknown_fault,
  [0x2b] = guest_unknown_fault,
  [0x2c] = guest_unknown_fault,
  [0x2d] = guest_unknown_fault,
  [0x2e] = guest_unknown_fault,
  [0x2f] = guest_unknown_fault,
  [0x30] = guest_unknown_fault,
  [0x31] = guest_unknown_fault,
  [0x32] = guest_unknown_fault,
  [0x33] = guest_unknown_fault,
  [0x34] = guest_unknown_fault,
  [0x35] = guest_unknown_fault,
  [0x36] = guest_unknown_fault,
  [0x37] = guest_unknown_fault,
  [0x38] = guest_unknown_fault,
  [0x39] = guest_unknown_fault,
  [0x3a] = guest_unknown_fault,
  [0x3b] = guest_unknown_fault,
  [0x3c] = guest_unknown_fault,
  [0x3d] = guest_ppi,
  [0x3e] = ex_regs_exception,
  [0x3f] = guest_irq
};
