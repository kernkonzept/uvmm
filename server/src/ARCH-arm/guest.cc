/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/unique_ptr>
#include <l4/cxx/ref_ptr>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/vbus/vbus>

#include "irq.h"
#include "guest.h"
#include "device_factory.h"

static cxx::unique_ptr<Vmm::Guest> guest;

extern "C" void vcpu_entry(l4_vcpu_state_t *vcpu);

asm
(
 "vcpu_entry:                     \n"
 "  mov    r6, sp                 \n"
 "  bic    sp, #7                 \n"
 "  sub    sp, sp, #16            \n"
 "  mrc    p15, 0, r5, c13, c0, 2 \n"
 "  stmia  sp, {r4, r5, r6, lr}   \n"
 "  bl     c_vcpu_entry           \n"
 "  movw   r2, #0xf803            \n"
 "  movt   r2, #0xffff            \n"
 "  mov    r3, #0                 \n"
 "  mov    r5, sp                 \n"
 "  ldmia  r5, {r4, r6, sp, lr}   \n"
 "  mcr    p15, 0, r6, c13, c0, 2 \n"
 "  mov    pc, #" L4_stringify(L4_SYSCALL_INVOKE) " \n"
);

extern "C" l4_msgtag_t c_vcpu_entry(l4_vcpu_state_t *vcpu_state);

l4_msgtag_t __attribute__((flatten))
c_vcpu_entry(l4_vcpu_state_t *vcpu)
{
  return guest->handle_entry(Vmm::Cpu(vcpu));
}

namespace Vmm {

Guest::Guest(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base)
: Generic_guest(ram, vm_base),
  _gic(Vdev::make_device<Gic::Dist>(4, 2)), // 4 * 32 spis, 2 cpus
  _timer(Vdev::make_device<Vdev::Core_timer>())
{
  if (_ram.vm_start() & ((1 << 27) - 1))
    Dbg().printf(
      "\033[01;31mWARNING: Guest memory not 128MB aligned!\033[m\n"
      "       If you run Linux as a guest, Linux will likely fail to boot\n"
      "       as it assumes a 128MB alignment of its memory.\n"
      "       Current guest RAM alignment is only %dMB\n",
      (1 << __builtin_ctz(_ram.vm_start())) >> 20);
  else if (_ram.vm_start() & ~0xf0000000)
    Dbg(Dbg::Info).printf(
        "WARNING: Guest memory not 256MB aligned!\n"
        "       If you run Linux as a guest, you might hit a bug\n"
        "       in the arch/arm/boot/compressed/head.S code\n"
        "       that misses an ISB after code has been relocated.\n"
        "       According to the internet a fix for this issue\n"
        "       is floating around.\n");
}

Guest *
Guest::create_instance(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base)
{
  guest.reset(new Guest(ram, vm_base));
  return guest.get();
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vmm::Guest *vmm,
                                    Vmm::Virt_bus *vbus,
                                    Vdev::Dt_node const &node)
  {
    Dbg info;
    if (!vbus->io_ds())
      {
        Err().printf("ERROR: ARM GIC virtualization does not work without passing GICD via the vbus\n");
        return nullptr; // missing hardware part, disable GIC
      }

    // attach GICD to VM
    auto gic = vmm->gic();
    vmm->register_mmio_device(gic, node);

    L4vbus::Device vdev;
    L4Re::chksys(vbus->bus()->root().device_by_hid(&vdev, "arm-gicc"),
                 "getting ARM GIC from IO");

    l4vbus_resource_t res;
    L4Re::chksys(vdev.get_resource(0, &res),
                 "getting memory resource");

    info.printf("ARM GIC: %08lx-%08lx\n", res.start, res.end);

    auto g2 = Vdev::make_device<Ds_handler>(vbus->io_ds(), 0,
                                            res.end - res.start + 1, res.start);
    vmm->register_mmio_device(cxx::move(g2), node, 1);
    return gic;
  }
};

static F f;
static Vdev::Device_type t1 = { "arm,cortex-a9-gic", nullptr, &f };
static Vdev::Device_type t2 = { "arm,cortex-a15-gic", nullptr, &f };

struct F_timer : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vmm::Guest *vmm, Vmm::Virt_bus *,
                                    Vdev::Dt_node const &)
  {
    return vmm->timer();
  }
};

static F_timer ftimer;
static Vdev::Device_type tt = { "arm,armv7-timer", nullptr, &ftimer };

} // namespace

L4virtio::Ptr<void>
Guest::load_linux_kernel(char const *kernel, l4_addr_t *entry)
{
  enum { Default_entry =  0x208000 };
  *entry = _ram.vm_start() + Default_entry;
  auto end = load_binary_at(kernel, Default_entry, entry);

  /* If the kernel relocates itself it either decompresses itself
   * directly to the final adress or it moves itself behind the end of
   * bss before starting decompression. So we should be safe if we
   * place anything (e.g. initrd/device tree) at 3/4 of the ram.
   */
  l4_size_t def_offs = l4_round_size((_ram.size() * 3) / 4,
                                     L4_SUPERPAGESHIFT);
  L4virtio::Ptr<void> def_end(_ram.vm_start() + def_offs);

  if (def_end.get() < end.get())
    L4Re::chksys(-L4_ENOMEM, "Not enough space to run Linux");

  Dbg().printf("Linux end at %llx, reserving space up to :%llx\n",
               end.get(), def_end.get());
  return def_end;
}

void
Guest::prepare_linux_run(Cpu vcpu, l4_addr_t entry, char const * /* kernel */,
                         char const * /* cmd_line */)
{
  // Set up the VCPU state as expected by Linux entry
  vcpu->r.flags = 0x00000013;
  vcpu->r.sp    = 0;
  vcpu->r.r[0]  = 0;
  vcpu->r.r[1]  = ~0UL;
  vcpu->r.r[2]  = has_device_tree() ? _device_tree.get() : 0;
  vcpu->r.r[3]  = 0;
  vcpu->r.ip    = entry;
}

void
Guest::run(Cpu vcpu)
{
  _vcpu[0] = &vcpu;

  vcpu->saved_state =  L4_VCPU_F_FPU_ENABLED
                         | L4_VCPU_F_USER_MODE
                         | L4_VCPU_F_IRQ
                         | L4_VCPU_F_PAGE_FAULTS
                         | L4_VCPU_F_EXCEPTIONS;
  vcpu->entry_ip = (l4_umword_t) &vcpu_entry;

  auto *vm = vcpu.state();

  vm->vm_regs.hcr &= ~(1 << 27);
  vm->vm_regs.hcr |= 1 << 13;
  _gic->set_cpu(0, &vm->gic);
  vmm_current_cpu_id = 0;

  L4::Cap<L4::Thread> myself;
  myself->vcpu_resume_commit(myself->vcpu_resume_start());
}

void
Guest::show_state_registers(FILE *mon)
{
  for (int i = 0; i < Nr_cpus; ++i)
    {
      //if (i != current_cpu())
      //  interrupt_vcpu(i);

      Cpu v = *_vcpu[i];
      fprintf(mon, "CPU %d:\n", i);
      fprintf(mon, "pc=%08lx lr=%08lx sp=%08lx flags=%08lx\n",
              v->r.ip, v->r.lr, v->r.sp, v->r.flags);
      fprintf(mon, " r0=%08lx  r1=%08lx  r2=%08lx  r3=%08lx\n",
              v->r.r[0], v->r.r[1], v->r.r[2], v->r.r[3]);
      fprintf(mon, " r4=%08lx  r5=%08lx  r6=%08lx  r7=%08lx\n",
              v->r.r[4], v->r.r[5], v->r.r[6], v->r.r[7]);
      fprintf(mon, " r8=%08lx  r9=%08lx r10=%08lx r11=%08lx\n",
              v->r.r[8], v->r.r[9], v->r.r[10], v->r.r[11]);
      fprintf(mon, "r12=%08lx\n",
              v->r.r[12]);
    }
}

void
Guest::show_state_interrupts(FILE *)
{
}

inline l4_msgtag_t
Guest::handle_entry(Cpu vcpu)
{
  auto *utcb = vcpu.saved_utcb();
  asm volatile("mcr p15, 0, %0, c13, c0, 2" : : "r"(utcb));
  auto hsr = vcpu.hsr();

  switch (hsr.ec())
    {
    case 0x20: // insn abt
      // fall through
    case 0x24: // data abt
      if (!handle_mmio(vcpu->r.pfa, vcpu))
        {
          Err().printf("cannot handle VM memory access @ %lx ip=%lx\n",
                       vcpu->r.pfa, vcpu->r.ip);
          halt_vm();
        }
      break;

    case 0x3d: // VIRTUAL PPI
      switch (hsr.svc_imm())
        {
        case 0: // VGIC IRQ
          _gic->handle_maintenance_irq(vmm_current_cpu_id);
          break;
        case 1: // VTMR IRQ
          _timer->inject();
          break;
        default:
          Err().printf("unknown virtual PPI: %d\n", (int)hsr.svc_imm());
          break;
        }
      break;

    case 0x3f: // IRQ
      handle_ipc(vcpu->i.tag, vcpu->i.label, utcb);
      break;

    case 0x01: // WFI, WFE
      if (hsr.wfe_trapped()) // WFE
        {
          // yield
        }
      else // WFI
        {
          if (_gic->schedule_irqs(vmm_current_cpu_id))
            {
              vcpu->r.ip += 2 << hsr.il();
              break;
            }

          l4_timeout_t to = L4_IPC_NEVER;
          auto *vm = vcpu.state();

          if ((vm->cntv_ctl & 3) == 1) // timer enabled and not masked
            {
              // calculate the timeout based on the VTIMER values !
              l4_uint64_t cnt, cmp;
              asm volatile ("mrrc p15, 1, %Q0, %R0, c14" : "=r"(cnt));
              asm volatile ("mrrc p15, 3, %Q0, %R0, c14" : "=r"(cmp));

              if (cmp <= cnt)
                {
                  vcpu->r.ip += 2 << hsr.il();
                  break;
                }

              l4_uint64_t diff = (cmp - cnt) / 24;
              if (0)
                printf("diff=%lld\n", diff);
              l4_rcv_timeout(l4_timeout_abs_u(l4_kip_clock(l4re_kip()) + diff, 8, utcb), &to);
            }

          wait_for_ipc(utcb, to);

          // skip insn
          vcpu->r.ip += 2 << hsr.il();
        }
      break;

    case 0x05: // MCR/MRC CP 14

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
          vcpu->r.r[hsr.mcr_rt()] = flip;
        }
      else if (   hsr.mcr_opc1() == 0
               && hsr.mcr_crn() == 0
               && hsr.mcr_crm() == 5
               && hsr.mcr_opc2() == 0) // DCC Get/Put
        {
          if (hsr.mcr_read())
            vcpu->r.r[hsr.mcr_rt()] = 0;
          else
            putchar(vcpu->r.r[hsr.mcr_rt()]);
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
      break;

    default:
      Err().printf("unknown trap: err=%lx ec=0x%x ip=%lx\n",
                   vcpu->r.err, (int)hsr.ec(), vcpu->r.ip);
      halt_vm();
    }

  process_pending_ipc(vcpu, utcb);

  _gic->schedule_irqs(vmm_current_cpu_id);

  L4::Cap<L4::Thread> myself;
  return myself->vcpu_resume_start(utcb);
}

} // namespace
