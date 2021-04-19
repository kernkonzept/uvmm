/*
 * Copyright (C) 2015-2018, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "binary_loader.h"
#include "device_factory.h"
#include "guest.h"
#include "guest_entry.h"

namespace Vmm {

Guest::Guest()
: _core_ic(Vdev::make_device<Gic::Mips_core_ic>()),
  _cm(Vdev::make_device<Vdev::Coherency_manager>(&_memmap)),
  _cpc(Vdev::make_device<Vdev::Mips_cpc>())
{
  _memmap[_cm->mem_region()] = _cm;
  _cm->register_cpc(_cpc);
}

void
Guest::setup_device_tree(Vdev::Device_tree dt)
{
  // advertise CPU core timer frequency in DTS
  auto node = dt.path_offset("/cpus");
  node.setprop_u32("mips-hpt-frequency", l4re_kip()->frequency_cpu * 1000);
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
Guest::prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const *binary, char const *cmd_line,
                          l4_addr_t dt_boot_addr)
{
  Vcpu_ptr vcpu = devs->cpus()->vcpu(0);
  Vm_ram *ram = devs->ram().get();

  /*
   * Setup arguments for Mips boot protocol
   */
  Guest_addr prom_tab(L4_PAGESIZE);

  size_t size = 2 * sizeof(l4_addr_t);
  auto prom_buf = prom_tab + size;

  size += strlen(binary) + 1;
  strcpy(ram->guest2host<char *>(prom_buf), binary);
  ram->guest2host<l4_addr_t *>(prom_tab)[0] = ram->guest_phys2boot(prom_buf);

  if (cmd_line)
    {
      strcpy(ram->guest2host<char *>(prom_tab + size), cmd_line);
      ram->guest2host<l4_addr_t *>(prom_tab)[1] = ram->guest_phys2boot(prom_tab + size);
      size += strlen(cmd_line) + 1;
    }

  l4_cache_clean_data(ram->guest2host<l4_addr_t>(prom_tab),
                      ram->guest2host<l4_addr_t>(prom_tab) + size);

  // Initial register setup:
  //  a0 - number of kernel arguments
  //  a1 - address of kernel arguments
  //  a2 - unused
  //  a3 - address of DTB
  vcpu->r.a0 = cmd_line ? 2 : 1;
  vcpu->r.a1 = ram->guest_phys2boot(prom_tab);
  vcpu->r.a2 = 0;
  vcpu->r.a3 = dt_boot_addr;
  vcpu->r.status = 8;
  // UHI boot protocol spec says that at least KX should be set when the
  // boot loader passes in 64bit addresses for the command line parameters.
  if (sizeof(l4_addr_t) == 8)
    vcpu->r.status |= 0xe0;
  vcpu->r.ip = entry;
}

void
Guest::run(cxx::Ref_ptr<Cpu_dev_array> const &cpus)
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
Guest::dispatch_hypcall(Hypcall_code hypcall_code, Vcpu_ptr vcpu)
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
Guest::handle_entry(Vcpu_ptr vcpu)
{
  auto *utcb = l4_utcb();
  unsigned cause = (vcpu->r.cause >> 2) & 0x1F;
  // XXX The above statement treats all Fiasco exception codes (0x100-0x102)
  //     equally as 0. In case of 0x101 (ex_regs triggered exception) this
  //     might be an issue as handle_ipc() might evaluate stale IPC regs.
  //     0x102 is defined but not used.
  assert((vcpu->r.cause & 0x1FF) <= 0x100);

  auto *s = vcpu.state();
  unsigned exccode = (s->guest_ctl_0 >> 2) & 0x1f;

  if ((cause != 27 || exccode != 2) && trace().is_active())
    trace().printf("VCPU %d Entry. IP = 0x%lx, cause: 0x%lx(%d), ctl0: 0x%lx\n",
                   vcpu.get_vcpu_id(), vcpu->r.ip, vcpu->r.cause, cause,
                   s->guest_ctl_0);

  switch (cause)
    {
    case 0:
      vcpu.handle_ipc(vcpu->i.tag, vcpu->i.label, utcb);
      break;
    case 1: // TLB modify
    case 2: // TLB load/fetch
    case 3: // TLB store
      if (Mips::Instruction(vcpu->r.bad_instr).is_cache_op())
        {
          // FIXME: cache coherency currently not handled
          // We assume that the memory will be coherent when mapped into
          // the guest on first access.
          info().printf("Cache operation on unmapped memory requested. Ignored. (Opcode: 0x%lx, address: 0x%lx)\n",
                        vcpu->r.bad_instr, vcpu->r.pfa);
          vcpu.jump_instruction();
          break;
        }
      switch (handle_mmio(vcpu->r.pfa, vcpu))
        {
        case Retry: break;
        case Jump_instr: vcpu.jump_instruction(); break;
        default:
          Err().printf(
            "Bad page fault (%s) 0x%lx (GExcCode=0x%x) @0x%lx. Halting.\n",
            cause == 2 ? "read" : "write", vcpu->r.pfa, exccode, vcpu->r.ip);
          halt_vm(vcpu);
          break;
        }
      break;
    case 27: // guest exception
      {
        Mips::Instruction insn(vcpu->r.bad_instr);
        if (!insn.raw)
          {
            Err().printf("Cannot decode faulting instruction @ IP 0x%lx\n",
                         vcpu->r.ip);
            halt_vm(vcpu);
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
              {
                // Index Store Tag must only be used to initialise caches, ignore.
                if (insn.cache_optype() != 2)
                  info().printf("Unhandled cache operation 0x%lx. Ignored.\n",
                                vcpu->r.bad_instr);
                // FIXME: assuming that cache coherency is guaranteed by Fiasco
                ret = Jump_instr;
              }
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
            halt_vm(vcpu);
          }
        if (ret == Jump_instr)
          vcpu.jump_instruction();
        break;
      }
    default:
      Err().printf("Unknown cause of VMM entry: %d. Halting.\n", cause);
      halt_vm(vcpu);
    }

  vcpu.process_pending_ipc(utcb);
  _core_ic->update_vcpu(vcpu);
}

namespace {

using namespace Vdev;

struct F : Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Device_lookup *devs,
                                    Vdev::Dt_node const &) override
  {
    // Device tree only sees the IC for core 0.
    return devs->vmm()->core_ic()->get_ic(0);
  }
};

static F f;
static Vdev::Device_type t = { "mti,cpu-interrupt-controller", nullptr, &f };

}

} // namespace
