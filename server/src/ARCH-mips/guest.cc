/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "binary_loader.h"
#include "device_factory.h"
#include "guest.h"
#include "guest_entry.h"

namespace {

l4_addr_t sign_ext(l4_uint32_t addr)
{ return (l4_addr_t) ((l4_mword_t) ((l4_int32_t) addr)); }

}

namespace Vmm {

Guest::Guest(L4::Cap<L4Re::Dataspace> ram, l4_addr_t vm_base)
: Guest::Generic_guest(ram, vm_base, sign_ext(0x80000000)),
  _core_ic(Vdev::make_device<Gic::Mips_core_ic>()),
  _cm(Vdev::make_device<Vdev::Coherency_manager>(&_memmap)),
  _cpc(Vdev::make_device<Vdev::Mips_cpc>())
{
  _memmap[_cm->mem_region()] = _cm;
  _cm->register_cpc(_cpc);
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
  Boot::Binary_ds image(kernel);
  if (image.is_elf_binary())
    *entry = image.load_as_elf(&_ram);
  else
    {
      image.load_as_raw(&_ram, 0x100000);
      *entry = _ram.boot_addr(0x100400);
    }

  return l4_round_size(image.get_upper_bound(), L4_LOG2_SUPERPAGESIZE);
}

void
Guest::prepare_linux_run(Cpu vcpu, l4_addr_t entry, char const *kernel,
                         char const *cmd_line)
{
  /*
   * Setup arguments for Mips boot protocol
   */
  L4virtio::Ptr<l4_addr_t> prom_tab(L4_PAGESIZE);

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

  l4_cache_clean_data(reinterpret_cast<l4_addr_t>(_ram.access(prom_tab)),
                      reinterpret_cast<l4_addr_t>(_ram.access(prom_tab)) + size);

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
Guest::run(cxx::Ref_ptr<Vcpu_array> const &cpus)
{
  _cpc->register_cpus(cpus);

  for (auto cpu: *cpus.get())
    {
      if (!cpu)
        continue;

      cpu->vcpu()->user_task = _task.cap();
      cpu->powerup_cpu();

      // attach the core IC
      _core_ic->create_ic(cpu->vcpu().get_vcpu_id(), cpu->thread_cap());
    }

  cpus->cpu(0)->set_coherent();
  cpus->cpu(0)->startup();
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
  auto *utcb = l4_utcb();
  unsigned cause = (vcpu->r.cause >> 2) & 0x1F;
  auto *s = vcpu.state();
  unsigned exccode = (s->guest_ctl_0 >> 2) & 0x1f;

  if ((cause != 27 || exccode != 2) && trace().is_active())
    trace().printf("VCPU %d Entry. IP = 0x%lx, cause: 0x%lx(%d), ctl0: 0x%lx\n",
                   vcpu.get_vcpu_id(), vcpu->r.ip, vcpu->r.cause, cause,
                   s->guest_ctl_0);

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
            else if (insn.is_cache_op())
              ret = Jump_instr; // cache coherence handled by Fiasco
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
            info().printf("Hardware change ignored @ IP 0x%lx\n", vcpu->r.ip);
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
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vmm::Guest *vmm,
                                    Vmm::Virt_bus *,
                                    Vdev::Dt_node const &)
  {
    // Device tree only sees the IC for core 0.
    return vmm->core_ic()->get_ic(0);
  }
};

static F f;
static Vdev::Device_type t = { "mti,cpu-interrupt-controller", nullptr, &f };

}

} // namespace
