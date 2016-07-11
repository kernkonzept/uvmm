/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/static_container>

#include "device_factory.h"
#include "guest.h"

static cxx::Static_container<Vmm::Guest> guest;

void handler(l4_vcpu_state_t *vcpu);

void __attribute__((flatten))
handler(l4_vcpu_state_t *vcpu)
{
  guest->handle_entry(Vmm::Cpu(vcpu));
}

namespace {

l4_addr_t sign_ext(l4_uint32_t addr)
{ return (l4_addr_t) ((l4_mword_t) ((l4_int32_t) addr)); }

}

namespace Vmm {

Guest::Guest(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base)
: Guest::Generic_guest(ram, vm_base, sign_ext(0x80000000)),
  _core_ic(Vdev::make_device<Gic::Mips_core_ic>())
{
  // TODO Fiasco should be exporting the proc ID for us. For the
  //      moment just derive it from the platform.
  auto *platform = l4re_kip()->platform_info.name;
  if (sizeof(l4_addr_t) == 8)
    _proc_id = 0x00010000; // generic 64bit CPU
  else if (strcmp(platform, "baikal_t") == 0)
    _proc_id = 0x0001a82c; // P5600
  else
    _proc_id = 0x0001a700; // M5150
}

Guest *
Guest::create_instance(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base)
{
  guest.construct(ram, vm_base);
  return guest;
}

void
Guest::update_device_tree(char const *cmd_line)
{
  Guest::Generic_guest::update_device_tree(cmd_line);

  // advertise CPU core timer frequency in DTS
  auto node = device_tree().path_offset("/cpus");
  node.setprop_u32("mips-hpt-frequency", l4re_kip()->frequency_cpu * 1000);
}

L4virtio::Ptr<void>
Guest::load_linux_kernel(char const *kernel, l4_addr_t *entry)
{
  *entry = _ram.boot_addr(0x100400);
  return l4_round_size(load_binary_at(kernel, 0x100000, entry),
                       L4_LOG2_SUPERPAGESIZE);
}

void
Guest::show_state_registers(FILE *f)
{
  for (int i = 0; i < 1; ++i)
    {
      //if (i != current_cpu)
      //  interrupt_vcpu(i);

      Cpu v = *_vcpu[i];
      fprintf(f, "CPU %d\n", i);
      fprintf(f, "EPC=%08lx SP=%08lx\n", v->r.ip, v->r.sp);
      fprintf(f, "Status=%08lx  Cause=%08lx\n", v->r.status, v->r.cause);
      fprintf(f, "ULR=%08lx  Hi=%08lx Lo=%08lx\n", v->r.ulr, v->r.hi, v->r.lo);
      fprintf(f, "at/ 1=%08lx v0/ 2=%08lx v1/ 3=%08lx\n",
              v->r.r[1], v->r.r[2], v->r.r[3]);
      fprintf(f, "a0/ 4=%08lx a1/ 5=%08lx a1/ 6=%08lx a4/ 7=%08lx\n",
              v->r.r[4], v->r.r[5], v->r.r[6], v->r.r[7]);
      fprintf(f, "t0/ 8=%08lx t1/ 9=%08lx t2/10=%08lx t3/11=%08lx\n",
              v->r.r[8], v->r.r[9], v->r.r[10], v->r.r[11]);
      fprintf(f, "t4/12=%08lx t5/13=%08lx t6/14=%08lx t7/15=%08lx\n",
              v->r.r[12], v->r.r[13], v->r.r[14], v->r.r[15]);
      fprintf(f, "s0/16=%08lx s1/17=%08lx s2/18=%08lx s3/19=%08lx\n",
              v->r.r[16], v->r.r[17], v->r.r[18], v->r.r[19]);
      fprintf(f, "s4/20=%08lx s5/21=%08lx s6/22=%08lx s7/23=%08lx\n",
              v->r.r[20], v->r.r[21], v->r.r[22], v->r.r[23]);
      fprintf(f, "t8/24=%08lx t9/25=%08lx k0/26=%08lx k1/27=%08lx\n",
              v->r.r[24], v->r.r[25], v->r.r[26], v->r.r[27]);
      fprintf(f, "gp/28=%08lx sp/29=%08lx s8/30=%08lx ra/31=%08lx\n",
              v->r.r[28], v->r.r[29], v->r.r[30], v->r.r[31]);

      auto *s = v.state();
      s->update_state(~0UL);
      fprintf(f, "\nGuestCtl0=%08lx  Guestctl0_ext=%08lx\n",
              s->guest_ctl_0, s->guest_ctl_0_ext);
      fprintf(f, "GuestCtl1=%08lx  Guestctl2    =%08lx\n",
              s->guest_ctl_1, s->guest_ctl_2);
      fprintf(f, "\nGuest CP0:\n");

      fprintf(f, "Status   =%08lx  Cause    =%08lx\n", s->g_status, s->g_cause);
      fprintf(f, "Index    =%08lx  EBase    =%08lx\n", s->g_index, s->g_ebase);
      fprintf(f, "EntryLo0 =%08lx  EntryLo1 =%08lx\n", s->g_entry_lo[0], s->g_entry_lo[1]);
      fprintf(f, "Context  =%08lx  EntryHi  =%08lx\n", s->g_context, s->g_entry_hi);
      fprintf(f, "PageMask =%08lx  PageGrain=%08lx\n", s->g_page_mask, s->g_page_grain);
      fprintf(f, "ULR      =%08lx  Wired    =%08lx\n", s->g_ulr, s->g_wired);
      fprintf(f, "SegCtl0  =%08lx  SegCtl1  =%08lx\n", s->g_seg_ctl[0], s->g_seg_ctl[1]);
      fprintf(f, "SegCtl2  =%08lx  HWRena   =%08lx\n", s->g_seg_ctl[2], s->g_hwrena);
      fprintf(f, "PWBase   =%08lx  PWField  =%08lx\n", s->g_pw_base, s->g_pw_field);
      fprintf(f, "PWSize   =%08lx  PWCtl    =%08lx\n", s->g_pw_size, s->g_pw_ctl);
      fprintf(f, "BadVAddr =%08lx  BadInstr =%08lx\n", s->g_bad_v_addr, s->g_bad_instr);
      fprintf(f, "BadInstrP=%08lx  Compare  =%08lx\n", s->g_bad_instr_p, s->g_compare);
      fprintf(f, "IntCtl   =%08lx  EPC      =%08lx\n", s->g_intctl, s->g_epc);
      fprintf(f, "Config0  =%08lx  Config1  =%08lx\n", s->g_cfg[0], s->g_cfg[1]);
      fprintf(f, "Config2  =%08lx  Config3  =%08lx\n", s->g_cfg[2], s->g_cfg[3]);
      fprintf(f, "Config4  =%08lx  Config5  =%08lx\n", s->g_cfg[4], s->g_cfg[5]);
    }
}

void
Guest::show_state_interrupts(FILE *f)
{
  for (int i = 0; i < 1; ++i)
    {
      //if (i != current_cpu)
      //  interrupt_vcpu(i);

      Cpu v = *_vcpu[i];

      fprintf(f, "\nCPU %d core IC:\n", i);
      _core_ic->show_state(f, v);
    }
}

void
Guest::prepare_linux_run(Cpu vcpu, l4_addr_t entry, char const *kernel,
                         char const *cmd_line)
{
  /*
   * Setup arguments for Mips boot protocol
   */
  l4_addr_t end = has_device_tree()
                  ? (_device_tree.get() + device_tree().size())
                  : 1;
  L4virtio::Ptr<l4_addr_t> prom_tab(l4_round_size(end, L4_PAGESHIFT));

  size_t size = 2 * sizeof(l4_addr_t);
  L4virtio::Ptr<char> prom_buf(prom_tab.get() + size);

  size += strlen(kernel) + 1;
  strcpy(_ram.access(prom_buf), kernel);
  _ram.access(prom_tab)[0] = _ram.boot_addr(prom_buf);

  if (cmd_line)
    {
      prom_buf = L4virtio::Ptr<char>(prom_buf.get() + size);
      size += strlen(cmd_line) + 1;
      strcpy(_ram.access(prom_buf), cmd_line);
      _ram.access(prom_tab)[1] = _ram.boot_addr(prom_buf);
    }

  l4_cache_clean_data(reinterpret_cast<l4_addr_t>(_ram.access(prom_tab)), size);

  // Initial register setup:
  //  a0 - number of kernel arguments
  //  a1 - address of kernel arguments
  //  a2 - unused
  //  a3 - address of DTB
  vcpu->r.a0 = cmd_line ? 2 : 1;
  vcpu->r.a1 = _ram.boot_addr(prom_tab);
  vcpu->r.a2 = 0;
  vcpu->r.a3 = has_device_tree() ? _ram.boot_addr(_device_tree) : 0;
  vcpu->r.status = 8;
  // UHI boot protocol spec says that at least KX should be set when the
  // boot loader passes in 64bit addresses for the command line parameters.
  if (sizeof(l4_addr_t) == 8)
    vcpu->r.status |= 0xe0;
  vcpu->r.ip = entry;
}

void
Guest::run(Cpu vcpu)
{
  _vcpu[0] = &vcpu;

  l4_umword_t sp;
  asm ("move %0, $sp" : "=r" (sp));

  vcpu->saved_state = L4_VCPU_F_FPU_ENABLED
                      | L4_VCPU_F_USER_MODE
                      | L4_VCPU_F_IRQ
                      | L4_VCPU_F_PAGE_FAULTS
                      | L4_VCPU_F_EXCEPTIONS;
  vcpu->entry_ip = (l4_umword_t)&handler;
  vcpu->entry_sp = sp & ~0xfUL;

  auto *s = vcpu.state();
  // disable trapping of CF1&2, CG and GT, enable ctl2
  s->guest_ctl_0 |= 0x3000083;
  s->guest_ctl_0_ext |= 0x10; // CGI
  l4_umword_t cca = s->g_cfg[0] & 7UL;
  s->g_seg_ctl[0] = 0x00200010;
  s->g_seg_ctl[1] = 0x00000002 | (cca << 16);
  s->g_seg_ctl[2] = 0x04300030 | (cca << 16) | cca;
  s->set_modified(L4_VM_MOD_GUEST_CTL_0
                  | L4_VM_MOD_GUEST_CTL_0_EXT
                  | L4_VM_MOD_CFG
                  | L4_VM_MOD_XLAT);

  Dbg(Dbg::Info).printf("Starting vmm @ 0x%lx (handler @ %p with stack @ %lx)\n",
                        vcpu->r.ip, &handler, sp);

  L4::Cap<L4::Thread> myself;
  auto e = l4_error(myself->vcpu_resume_commit(myself->vcpu_resume_start()));

  Err().printf("VMM exited with %ld\n", e);
}

int
Guest::dispatch_hypcall(Hypcall_code hypcall_code, Cpu &vcpu)
{
  switch (hypcall_code)
  {
  case Hypcall_outchar:
    _hypcall_print.print_char(vcpu->r.a0);
    return Jump_instr;

  };

  return -L4_ENOSYS;
}

void
Guest::handle_entry(Cpu vcpu)
{
  if (!(vcpu->r.status & (1UL << 3)))
    {
      Err().printf("Exception in entry handler. Halting. IP = 0x%lx\n",
                   vcpu->r.ip);
      halt_vm();
    }

  auto *utcb = l4_utcb();
  unsigned cause = (vcpu->r.cause >> 2) & 0x1F;
  auto *s = vcpu.state();
  unsigned exccode = (s->guest_ctl_0 >> 2) & 0x1f;

  if (0 && (cause != 27 || exccode != 2))
    Dbg(Dbg::Info).printf("VMM Entry. IP = 0x%lx, cause: 0x%lx(%d), ctl0: 0x%lx\n",
                        vcpu->r.ip, vcpu->r.cause, cause, s->guest_ctl_0);

  switch (cause)
    {
    case 0:
      handle_ipc(vcpu->i.tag, vcpu->i.label, utcb);
      break;
    case 1: // TLB modify
    case 2: // TLB load/fetch
    case 3: // TLB store
      if (!handle_mmio(vcpu->r.pfa, vcpu))
        {
          Err().printf("Bad page fault (%s) 0x%lx (GExcCode=0x%x) @0x%lx. Halting.\n",
                       cause == 2 ? "read" : "write", vcpu->r.pfa, exccode, vcpu->r.ip);
          halt_vm();
        }
      break;
    case 27: // guest exception
      {
        Mips::Instruction insn(vcpu->r.bad_instr);
        if (!insn.raw)
          {
            Err().printf("Cannot decode faulting instruction @ IP 0x%lx\n",
                         vcpu->r.ip);
            halt_vm();
          }

        int ret = -L4_ENOSYS;
        switch (exccode)
          {
          case 0: // sensitive instruction
            if (insn.is_mfc0())
              ret = handle_gpsi_mfc0(vcpu, insn);
            else if (insn.is_mtc0())
              ret = handle_gpsi_mtc0(vcpu, insn);
            else if (insn.is_wait())
              ret = handle_wait(vcpu, utcb);
            break;

          case 1: // software field change
            if (insn.is_mtc0())
              ret = handle_software_field_change(vcpu, insn);
            break;

          case 2: // hypcall
            if (insn.is_hypcall())
              ret = dispatch_hypcall((Hypcall_code)(unsigned)insn.hypcall_code(), vcpu);
            break;

          case 9: // hardware field change
            Dbg().printf("Hardware change @ IP 0x%lx\n", vcpu->r.ip);
            ret = 0; // ignored
            break;
          case 10:
            Err().printf("Bad TLB root access 0x%lx @0x%lx. Halting.\n",
                         vcpu->r.pfa, vcpu->r.ip);
            break;
          }

        if (ret < 0)
          {
            Err().printf("Guest exception %d, error: %d, inst: 0x%x @ IP 0x%lx\n",
                         exccode, ret, insn.raw, vcpu->r.ip);
            halt_vm();
          }
        if (ret == Jump_instr)
          vcpu.jump_instruction();
        break;
      }
    default:
      Err().printf("Unknown cause of VMM entry: %d. Halting.\n", cause);
      halt_vm();
    }

  process_pending_ipc(vcpu, utcb);
  _core_ic->update_vcpu(vcpu);

  L4::Cap<L4::Thread> myself;
  auto e = l4_error(myself->vcpu_resume_commit(myself->vcpu_resume_start()));

  Err().printf("VM restart failed with %ld\n", e);
  halt_vm();
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vmm::Guest *vmm,
                                    Vmm::Virt_bus *,
                                    Vdev::Dt_node const &)
  {
    return vmm->core_ic();
  }
};

static F f;
static Vdev::Device_type t = { "mti,cpu-interrupt-controller", nullptr, &f };

}

} // namespace
