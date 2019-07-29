/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/unique_ptr>
#include <l4/cxx/ref_ptr>
#include <l4/re/error_helper>
#include <l4/vbus/vbus>

#include "binary_loader.h"
#include "device_factory.h"
#include "guest.h"
#include "guest_subarch.h"
#include "irq.h"
#include "irq_dt.h"
#include "pm.h"
#include "virt_bus.h"

#include "vm_print.h"

static cxx::unique_ptr<Vmm::Guest> guest;

__thread unsigned vmm_current_cpu_id;

typedef void (*Entry)(Vmm::Vcpu_ptr vcpu);

namespace Vmm {

Guest::Guest()
: _gic(Vdev::make_device<Gic::Dist>(16, Vmm::Cpu_dev::Max_cpus))
{
  register_vm_handler(Hvc, Vdev::make_device<Vm_print_device>());
}

Guest *
Guest::create_instance()
{
  guest.reset(new Guest());
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
    // attach GICD to VM
    devs->vmm()->register_mmio_device(gic, Region_type::Virtual, node);
    // attach GICC to VM
    devs->vmm()->map_gicc(devs, node);
    return gic;
  }
};

static F f;
static Vdev::Device_type t1 = { "arm,cortex-a9-gic", nullptr, &f };
static Vdev::Device_type t2 = { "arm,cortex-a15-gic", nullptr, &f };
static Vdev::Device_type t3 = { "arm,cortex-a7-gic", nullptr, &f };
static Vdev::Device_type t4 = { "arm,gic-400", nullptr, &f };

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

    auto timer = Vdev::make_device<Vdev::Core_timer>(it.ic().get(), it.irq(), node);

    devs->vmm()->set_timer(timer);
    return timer;
  }
};

static F_timer ftimer;
static Vdev::Device_type tt1 = { "arm,armv7-timer", nullptr, &ftimer };
static Vdev::Device_type tt2 = { "arm,armv8-timer", nullptr, &ftimer };

/**
 * Mmio access handler that maps the GICC page.
 *
 * This handler maps the page during the eager-mapping stage before the
 * guest is started. It is also able to respond to page faults in the region
 * and will map the page again. Note, however, that this should normally
 * not happen because the page is pinned in the VM task during its life time.
 * Therefore a warning is printed when the access() function is called.
 */
class Gicc_region_mapper : public Vmm::Mmio_device
{
public:
  Gicc_region_mapper(l4_addr_t base)
  : _fp(l4_fpage(base, L4_PAGESHIFT, L4_FPAGE_RW))
  {}

  int access(l4_addr_t, l4_addr_t, Vcpu_ptr,
             L4::Cap<L4::Vm> vm, l4_addr_t, l4_addr_t) override
  {
    Dbg(Dbg::Core, Dbg::Warn)
      .printf("Access to GICC page trapped into guest handler. Restoring mapping.\n");

    remap_page(vm);

    return Retry;
  }

  void map_eager(L4::Cap<L4::Vm> vm, Vmm::Guest_addr, Vmm::Guest_addr) override
  { remap_page(vm); }

  static void
  update_reg_entry(l4_uint64_t base, l4_uint64_t size, bool strip,
                   Vdev::Dt_node const &node)
  {
    l4_uint64_t gicd_base, gicd_size;
    int res;

    Dbg(Dbg::Irq, Dbg::Info, "GIC")
      .printf("GICC virtualization only supports sizes up to 0x1000,"
              " adjusting device tree node\n");
    if (size > L4_PAGESIZE)
      {
        Dbg(Dbg::Irq, Dbg::Info, "GIC")
          .printf("GIC %s.reg update: Adjusting GICC size from %llx to %lx\n",
                  node.get_name(), size, L4_PAGESIZE);
      }
    if (strip)
      Dbg(Dbg::Irq, Dbg::Info, "GIC")
        .printf("GIC %s.reg update: Stripping superfluous entries\n",
                node.get_name());

    // Get GICD entry
    if ((res = node.get_reg_val(0, &gicd_base, &gicd_size)) < 0)
      {
        Err().printf("Failed to read 'reg[0]' from node %s: %s\n",
                     node.get_name(), node.strerror(res));
        throw L4::Runtime_error(-L4_EINVAL,
                                "Reading device tree entry for GIC");
      }

    // rewrite reg_entry
    size = size < L4_PAGESIZE ? size : L4_PAGESIZE;
    node.set_reg_val(gicd_base, gicd_size);
    node.append_reg_val(base, size);
  }

  static l4_uint64_t
  verify_node(Vdev::Dt_node const &node)
  {
    l4_uint64_t base, size, dummy;
    int res = node.get_reg_val(1, &base, &size);
    if (res < 0)
      {
        Err().printf("Failed to read 'reg[1]' from node %s: %s\n",
                     node.get_name(), node.strerror(res));
        throw L4::Runtime_error(-L4_EINVAL,
                                "Reading device tree entry for GIC");
      }

    // Check the alignment of the GICC page
    if (base & (L4_PAGESIZE - 1))
      {
        Err().printf("%s:The GICC page is not page aligned: <%llx, %llx>.\n",
                     node.get_name(), base, size);
        L4Re::chksys(-L4_EINVAL, "Setting up GICC page");
      }

    // Do we have to adapt the device tree?
    bool strip = node.get_reg_val(2, &dummy, &dummy) >= 0;
    if ((size > L4_PAGESIZE) || strip)
      update_reg_entry(base, size, strip, node);

    return base;
  }

private:
  void remap_page(L4::Cap<L4::Vm> vm) const
  {
    Dbg(Dbg::Mmio, Dbg::Info, "mmio")
      .printf("\tMapping [GICC] -> [%lx - %lx]\n", l4_fpage_memaddr(_fp),
              l4_fpage_memaddr(_fp) + L4_PAGESIZE);
    L4Re::chksys(vm->vgicc_map(_fp), "Mapping VGICC area into guest task");
  }

  l4_fpage_t _fp;
};



} // namespace

void
Guest::map_gicc(Device_lookup *devs, Vdev::Dt_node const &node) const
{
  l4_uint64_t base = Gicc_region_mapper::verify_node(node);
  auto gerr = Vdev::make_device<Gicc_region_mapper>(base);
  devs->vmm()->register_mmio_device(cxx::move(gerr), Region_type::Kernel,
                                    node, 1);
}

void
Guest::check_guest_constraints(l4_addr_t base) const
{
  Dbg warn(Dbg::Mmio, Dbg::Warn, "ram");

  if (guest_64bit)
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
Guest::load_linux_kernel(Vm_ram *ram, char const *kernel, Ram_free_list *free_list)
{
  Guest_addr ram_base = free_list->first_free_address();

  l4_addr_t entry = ~0ul;
  Boot::Binary_ds image(kernel);
  if (image.is_elf_binary())
    {
      entry = image.load_as_elf(ram, free_list);
      guest_64bit = image.is_elf64();
      if (!Guest_64bit_supported && guest_64bit)
        L4Re::chksys(-L4_EINVAL, "Running a 64bit guest on a 32bit host is "
                                 "not possible.");
    }
  else
    {
      char const *h = reinterpret_cast<char const *>(image.get_header());

      if (Guest_64bit_supported
          && h[0x38] == 'A' && h[0x39] == 'R'
          && h[0x3A] == 'M' && h[0x3B] == '\x64') // Linux header ARM\x64
        {
          l4_uint64_t l = *reinterpret_cast<l4_uint64_t const *>(&h[8]);
          // Bytes 0xc-0xf have the size
          entry = image.load_as_raw(ram, ram_base + l, free_list);
          this->guest_64bit = true;
        }
      else if (   h[0x24] == 0x18 && h[0x25] == 0x28
               && h[0x26] == 0x6f && h[0x27] == 0x01) // Linux magic
        {
          l4_uint32_t l = *reinterpret_cast<l4_uint32_t const *>(&h[0x28]);
          // Bytes 0x2c-0x2f have the zImage size
          entry = image.load_as_raw(ram, ram_base + l, free_list);
        }

      if (entry == ~0ul)
        {
          enum { Default_entry =  0x208000 };
          entry = image.load_as_raw(ram, ram_base + Default_entry, free_list);
        }
    }

  check_guest_constraints(ram_base.get());

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
  if (Guest_64bit_supported && guest_64bit)
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
Guest::prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry,
                         Vm_ram * /* ram */, char const * /* kernel */,
                         char const * /* cmd_line */, l4_addr_t dt_boot_addr)
{
  prepare_vcpu_startup(vcpu, entry);

  // Set up the VCPU state as expected by Linux entry
  if (Guest_64bit_supported && guest_64bit)
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

  for (auto cpu: *cpus.get())
    {
      if (!cpu)
        continue;

      auto vcpu = cpu->vcpu();

      vcpu->user_task = _task.cap();
      cpu->powerup_cpu();
      info().printf("Powered up cpu%d [%p]\n", vcpu.get_vcpu_id(),
                    cpu.get());

      _gic->set_cpu(vcpu.get_vcpu_id(), *vcpu, cpu->thread_cap());
    }
  cpus->cpu(0)->mark_on_pending();
  cpus->cpu(0)->startup();
}

l4_msgtag_t
Guest::handle_entry(Vcpu_ptr vcpu)
{
  auto *utcb = l4_utcb();

  process_pending_ipc(vcpu, utcb);
  _gic->schedule_irqs(vmm_current_cpu_id);

  L4::Cap<L4::Thread> myself;
  return myself->vcpu_resume_start(utcb);
}

void
Guest::handle_vm_call(Vcpu_ptr vcpu)
{
  bool res = false;
  // Check if this is a valid/supported SMCCC call
  if (Smccc_device::is_valid_call(vcpu->r.r[0]))
    {
      for (auto h: _hvc_handlers)
        if ((res = h->vm_call(vcpu)))
          break;
    }

  if (!res)
    {
      warn().printf("No handler for hvc call: imm=%lx a0=%lx a1=%lx ip=%lx "
                    "lr=%lx\n",
                    vcpu->r.err & 0xffff, vcpu->r.r[0], vcpu->r.r[1],
                    vcpu->r.ip, vcpu.get_lr());
      vcpu->r.r[0] = Smccc_device::Not_supported;
    }
}

static void dispatch_vm_call(Vcpu_ptr vcpu)
{
  guest->handle_vm_call(vcpu);
}

void
Guest::handle_smc_call(Vcpu_ptr vcpu)
{
  bool res = false;
  // Check if this is a valid/supported SMCCC call
  if (Smccc_device::is_valid_call(vcpu->r.r[0]))
    {
      for (auto h: _smc_handlers)
        if ((res = h->vm_call(vcpu)))
          break;
    }

  if (!res)
    {
      warn().printf("No handler for SMC call: a0=%lx a1=%lx ip=%lx lr=%lx\n",
                    vcpu->r.r[0], vcpu->r.r[1], vcpu->r.ip, vcpu.get_lr());
      vcpu->r.r[0] = Smccc_device::Not_supported;
    }

  vcpu->r.ip += 4;
}

static void dispatch_smc(Vcpu_ptr vcpu)
{
  guest->handle_smc_call(vcpu);
}

static void
guest_unknown_fault(Vcpu_ptr vcpu)
{
  Err().printf("unknown trap: err=%lx ec=0x%x ip=%lx lr=%lx\n",
               vcpu->r.err, (int)vcpu.hsr().ec(), vcpu->r.ip, vcpu.get_lr());
  guest->halt_vm();
}

static void
guest_memory_fault(Vcpu_ptr vcpu)
{
  switch (guest->handle_mmio(vcpu->r.pfa, vcpu))
    {
    case Retry: break;
    case Jump_instr: vcpu.jump_instruction(); break;
    default:
      Err().printf("cannot handle VM memory access @ %lx ip=%lx lr=%lx\n",
                   vcpu->r.pfa, vcpu->r.ip, vcpu.get_lr());
      guest->halt_vm();
      break;
    }
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

  wait_for_ipc(utcb, to);
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
      Err().printf("unknown virtual PPI: %d\n", (int)vcpu.hsr().svc_imm());
      break;
    }
}

static void
guest_ppi(Vcpu_ptr vcpu)
{ guest->handle_ppi(vcpu); }

static void guest_irq(Vcpu_ptr vcpu)
{
  guest->handle_ipc(vcpu->i.tag, vcpu->i.label, l4_utcb());
}

static void guest_mcr_access(Vcpu_ptr vcpu)
{
  auto hsr = vcpu.hsr();
  if (   hsr.mcr_opc1() == 0
      && hsr.mcr_crn() == 0
      && hsr.mcr_crm() == 1
      && hsr.mcr_opc2() == 0
      && hsr.mcr_read()) // DCC Status
    {
      // printascii in Linux is doing busyuart which wants to see a
      // busy flag to quit its loop while waituart does not want to
      // see a busy flag; this little trick makes it work
      static l4_umword_t flip;
      flip ^= 1 << 29;
      vcpu.set_gpr(hsr.mcr_rt(), flip);
    }
  else if (   hsr.mcr_opc1() == 0
           && hsr.mcr_crn() == 0
           && hsr.mcr_crm() == 5
           && hsr.mcr_opc2() == 0) // DCC Get/Put
    {
      if (hsr.mcr_read())
        vcpu.set_gpr(hsr.mcr_rt(), 0);
      else
        putchar(vcpu.get_gpr(hsr.mcr_rt()));
    }
  else
    {
      if (   hsr.mcr_opc1() == 0
          && hsr.mcr_crn() == 0
          && hsr.mcr_crm() == 0
          && hsr.mcr_opc2() == 0
          && hsr.mcr_read())
        printf("Unhandled DCC request: Non-ARMv7 guest?\n");

      printf("%08lx: %s p14, %d, r%d, c%d, c%d, %d (hsr=%08lx)\n",
             vcpu->r.ip, hsr.mcr_read() ? "MRC" : "MCR",
             (unsigned)hsr.mcr_opc1(),
             (unsigned)hsr.mcr_rt(),
             (unsigned)hsr.mcr_crn(),
             (unsigned)hsr.mcr_crm(),
             (unsigned)hsr.mcr_opc2(),
             (l4_umword_t)hsr.raw());
    }

  vcpu->r.ip += 2 << hsr.il();
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
  [0x03] = guest_unknown_fault,
  [0x04] = guest_unknown_fault,
  [0x05] = guest_mcr_access,
  [0x06] = guest_unknown_fault,
  [0x07] = guest_unknown_fault,
  [0x08] = guest_unknown_fault,
  [0x09] = guest_unknown_fault,
  [0x0a] = guest_unknown_fault,
  [0x0b] = guest_unknown_fault,
  [0x0c] = guest_unknown_fault,
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
  [0x3e] = guest_unknown_fault,
  [0x3f] = guest_irq
};
