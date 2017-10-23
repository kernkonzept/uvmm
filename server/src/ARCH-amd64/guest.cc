/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/static_container>
#include <l4/sys/kdebug.h>
#include <l4/sys/debugger.h>
#include <l4/re/util/env_ns>

#include "binary_loader.h"
#include "guest.h"
#include "debug.h"
#include "virtio_console.h"
#include "vm_state_vmx.h"
#include "consts.h"
#include "vmx_exit_to_str.h"

static cxx::Static_container<Vmm::Guest> guest;

namespace Vmm {

Guest *
Guest::create_instance()
{
  trace().printf("creating instance\n");
  guest.construct();
  return guest;
}

void Guest::register_io_device(cxx::Ref_ptr<Io_device> const &dev,
                               l4_addr_t start, l4_size_t sz)
{
  auto region = Region::ss(start, sz);

  // Check for overlapping regions!
  if (_iomap.count(region) != 0)
    throw L4::Runtime_error(L4_EINVAL, "IO map entry overlapping.");

  _iomap[region] = dev;

  trace().printf("New io mappping: %p @ [0x%lx, 0x%zx]\n", dev.get(), start, sz);
}

L4virtio::Ptr<void>
Guest::load_linux_kernel(Ram_ds *ram, char const *kernel, l4_addr_t *entry)
{
  Boot::Binary_ds image(kernel);

  if (image.is_elf_binary())
    throw  L4::Runtime_error(-L4_EINVAL, "ELF binaries are not supported.");

  l4_uint8_t num_setup_sects = *((char*)image.get_header() + Bp_setup_sects);
  trace().printf("number of setup sections found: 0x%x\n", num_setup_sects);

  // 512 is the size of a segment
  l4_addr_t setup_sects_size = (num_setup_sects + 1) * 512;

  if (Linux_kernel_start_addr < setup_sects_size)
    throw L4::Runtime_error(-L4_EINVAL,
                            "Supplied kernel image contains an invalid number "
                            " of setup sections (zeropage).");

  *entry = Linux_kernel_start_addr - setup_sects_size;
  trace().printf("size of setup sections: 0x%lx\n", setup_sects_size);
  trace().printf("loading binary at: 0x%lx\n", *entry);

  // load the binary starting after the boot_params
  auto z = image.load_as_raw(ram, *entry);
  trace().printf("Loaded kernel image as raw to 0x%lx\n", z);
  trace().printf("load kernel as raw entry to 0x%lx\n",
                 ram->boot_addr(Linux_kernel_start_addr));


  return l4_round_size(image.get_upper_bound(), L4_LOG2_SUPERPAGESIZE);
}

void Guest::prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry, Ram_ds *ram,
                              char const * /* kernel */, char const *cmd_line,
                              l4_addr_t dt_boot_addr)
{
  // use second memory page as zeropage location
  Zeropage zpage(L4_PAGESIZE, entry);

  // read initrd addr and size from device tree
  L4virtio::Ptr<void> dt_addr(dt_boot_addr);
  auto dt = Vdev::Device_tree(ram->access(dt_addr));
  int prop_sz1, prop_sz2;
  auto node = dt.path_offset("/chosen");
  auto prop_start = node.get_prop<fdt32_t>("linux,initrd-start", &prop_sz1);
  auto prop_end = node.get_prop<fdt32_t>("linux,initrd-end", &prop_sz2);

  if (prop_start && prop_end)
    {
      auto rd_start = node.get_prop_val(prop_start, prop_sz1, 0);
      auto rd_end = node.get_prop_val(prop_end, prop_sz2, 0);
      zpage.add_ramdisk(rd_start, rd_end - rd_start);
    }
  else
      Dbg().printf("No ramdisk found in device tree.");

  if (cmd_line)
    zpage.add_cmdline(cmd_line);

  zpage.cfg_e820(ram->size());
  // write zeropage to VM ram
  zpage.write(ram);

  vcpu->r.ip = *(reinterpret_cast<l4_addr_t*>(zpage.entry(ram)));
  vcpu->r.si = zpage.addr();

  trace().printf("Zeropage setup: vCPU ip: 0x%lx, si: 0x%lx\n", vcpu->r.ip,
                 vcpu->r.si);
}

int
Guest::handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                        l4_vcpu_regs_t *regs)
{
  l4_umword_t op_mask = (1ULL << ((1 << op_width) * 8)) - 1;

  auto f = _iomap.find(port);
  if (f == _iomap.end())
    {
      if (is_in)
        regs->ax = -1 & op_mask;

      trace().printf("WARNING: Unhandled IO access %s@0x%x/%d => 0x%lx\n",
                     is_in ? "IN" : "OUT", port, (op_width + 1) * 8, regs->ax);
      return Jump_instr;
    }

  port -= f->first.start;
  if (is_in)
    {
      l4_uint32_t out = -1;
      f->second->io_in(port, op_width, &out);

      regs->ax = (regs->ax & ~op_mask) | (out & op_mask);
    }
  else
    f->second->io_out(port, op_width, regs->ax & op_mask);

  return Jump_instr;
}

int
Guest::handle_cpuid(l4_vcpu_regs_t *regs)
{
  unsigned int a,b,c,d;
  auto rax = regs->ax;

  asm("cpuid"
      : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
      : "0"(rax), "2"(regs->cx));

  enum : unsigned long
  {
    Ecx_monitor_bit = (1UL << 3),
    Ecx_vmx_bit = (1UL << 5),
    Ecx_smx_bit = (1UL << 6),
    Ecx_x2apic_bit = (1UL << 21),
    Ecx_xsave_bit = (1UL << 26),
    Ecx_hypervisor_bit = (1UL << 31),

    Edx_rdtsc_bit = (1UL << 4),
    Edx_apic_bit = (1UL << 9),
    Edx_mtrr_bit = (1UL << 12),

    Kvm_feature_clocksource_bit = 1UL,

    Rdtscp_bit = (1UL << 27),

    Xsave_opt = 1,
    Xsave_c = (1UL << 1),
    Xget_bv = (1UL << 2),
    Xsave_s = (1UL << 3),
  };

  switch (rax)
    {
    case 0x1:
      // hide some CPU features
      c &= ~(  Ecx_monitor_bit
             | Ecx_vmx_bit
             | Ecx_smx_bit
// if xsave is filtered out, CR4 bit not set, busybox userland will fail
//             | Ecx_xsave_bit
             | Ecx_hypervisor_bit
            );

      d &= ~(Edx_mtrr_bit);
      break;

    case 0xa:
      a &= ~0xffULL;  // disable perfmon
      break;

    case 0xd:
      if (regs->cx == 1)
        {
          trace().printf("Filtering out xsave capabilities\n");
          a &= ~(  Xsave_opt
                   | Xsave_c
                   | Xget_bv // with ECX=1
                   | Xsave_s   // XSAVES/XRSTORS and IA32_XSS MSR
                );
        }
      break;

    case 0x80000001:
      {
        d &= ~( Rdtscp_bit );
        break;
      }
    }

  regs->ax = a;
  regs->bx = b;
  regs->cx = c;
  regs->dx = d;

  return Jump_instr;
}

int
Guest::handle_vm_call(l4_vcpu_regs_t *regs)
{
  if (regs->ax == 0)
    {
       _hypcall_print.print_char(regs->cx);
      return Jump_instr;
    }

  Err().printf("Unknown VMCALL 0x%lx\n", regs->ax);
  return -L4_ENOSYS;
}

int
Guest::handle_exit_vmx(Vmm::Vcpu_ptr vcpu)
{
  Vmx_state *vms = dynamic_cast<Vmx_state *>(vcpu.vm_state());
  assert(vms);

  using Exit = Vmx_state::Exit;
  auto reason = vms->exit_reason();
  auto *regs = &vcpu->r;

  if (reason != Vmx_state::Exit::Exec_vmcall)
    Dbg(Dbg::Guest, Dbg::Trace)
      .printf("Exit at guest IP 0x%lx with 0x%llx (Qual: 0x%llx)\n", vms->ip(),
              vms->vmx_read(L4VCPU_VMCS_EXIT_REASON),
              vms->vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION));

  enum Apic_access_exit_qualifications
  {
    Page_offset_length = 12,
    Page_offset_mask = (1 << Page_offset_length) - 1,
  };

  switch (reason)
    {
    case Exit::Cpuid: return handle_cpuid(regs);

    case Exit::Exec_vmcall: return handle_vm_call(regs);

    case Exit::Io_access:
      {
        auto qual = vms->vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION);
        int qw = qual & 7;

        Dbg(Dbg::Dev, Dbg::Trace).printf("IO @ guest with qual 0x%llx\n", qual);
        if (((qual >> 16) & 0xFFFF) == 0xcfb)
          Dbg(Dbg::Dev, Dbg::Trace)
            .printf(" 0xcfb access from ip: %lx\n", vms->ip());

        Mem_access::Width wd = Mem_access::Wd32;
        switch(qw)
          {
          // only 0,1,3 are valid values in the exit qualification.
          case 0: wd = Mem_access::Wd8; break;
          case 1: wd = Mem_access::Wd16; break;
          case 3: wd = Mem_access::Wd32; break;
          }

        return handle_io_access((qual >> 16) & 0xFFFF, qual & 8, wd, regs);
      }

    // Ept_violation needs to be checked here, as handle_mmio needs a vCPU ptr,
    // which cannot be passed to Vm_state/Vmx_state due to dependency reasons.
    case Exit::Ept_violation:
      {
        auto guest_phys_addr =
          vms->vmx_read(L4VCPU_VMCS_GUEST_PHYSICAL_ADDRESS);
        auto qual = vms->vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION);

        trace().printf("Exit reason due to EPT violation %i;  gp_addr 0x%llx, "
                       "qualification 0x%llx\n",
                       static_cast<unsigned>(reason), guest_phys_addr, qual);

        switch(handle_mmio(guest_phys_addr, vcpu))
          {
          case Retry: return L4_EOK;
          case Jump_instr: return Jump_instr;
          default: break;
          }

        warn().printf("Unhandled pagefault @ 0x%lx\n", vms->ip());
        warn().printf("Read: %llu, Write: %llu, Inst.: %llu Phys addr: 0x%llx\n",
                     qual & 1, qual & 2, qual & 4, guest_phys_addr);

        if (qual & 0x80)
          warn().printf("Linear address: 0x%llx\n",
                       vms->vmx_read(L4VCPU_VMCS_GUEST_LINEAR_ADDRESS));
        return -L4_EINVAL;
      }

    // VMX specific exits
    case Exit::Exception_or_nmi:
    case Exit::External_int:
      return vms->handle_exception_nmi_ext_int();

    case Exit::Interrupt_window:
      return L4_EOK;

    case Exit::Exec_halt:
      trace().printf("HALT 0x%llx!\n", vms->vmx_read(L4VCPU_VMCS_GUEST_RIP));
      vms->vmx_write(L4VCPU_VMCS_GUEST_ACTIVITY_STATE, 1);
      current_lapic(vcpu)->wait_for_irq();
      vms->unhalt();
      return L4_EOK;

    case Exit::Cr_access:
      return vms->handle_cr_access(regs);

    case Exit::Exec_rdmsr:
      return vms->handle_exec_rmsr(regs, current_lapic(vcpu));

    case Exit::Exec_wrmsr:
      return vms->handle_exec_wmsr(regs, current_lapic(vcpu));

    case Exit::Virtualized_eoi:
      Dbg().printf("INFO: EOI virtualized for vector 0x%llx\n",
                   vms->vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION));
      // Trap like exit: IP already on next instruction
      return L4_EOK;

    case Exit::Exec_xsetbv:
      if (regs->cx == 0)
        {
          l4_uint64_t value = (l4_uint64_t(regs->ax) & 0xFFFFFFFF)
                              | (l4_uint64_t(regs->dx) << 32);
          vms->vmx_write(L4_VM_VMX_VMCS_XCR0, value);
          Dbg().printf("Setting xcr0 to 0x%llx\n", value);
          return Jump_instr;
        }
      Dbg().printf("Writing unknown extended control register %ld\n", regs->cx);
      return -L4_EINVAL;

    case Exit::Apic_write:
      // Trap like exit: IP already on next instruction
      assert(0); // Not supported
      return L4_EOK;

    default:
      Dbg().printf("Exit at guest IP 0x%lx with 0x%llx (Qual: 0x%llx)\n",
                   vms->ip(), vms->vmx_read(L4VCPU_VMCS_EXIT_REASON),
                   vms->vmx_read(L4VCPU_VMCS_EXIT_QUALIFICATION));
      if (reason <= Exit::Exit_reason_max)
        Dbg().printf("Unhandled exit reason: %s (%d)\n",
                     str_exit_reason[(int)reason],
                     static_cast<unsigned>(reason));
      else
        Dbg().printf("Unknown exit reason: 0x%x\n",
                     static_cast<unsigned>(reason));
      return -L4_ENOSYS;
    }
}

void
Guest::run(cxx::Ref_ptr<Cpu_dev_array> const &cpus)
{
  cpus->cpu(0)->powerup_cpu();
  cpus->cpu(0)->startup();
  Vcpu_ptr vcpu0 = cpus->vcpu(0);
  vcpu0->user_task = _task.cap();

  // TODO loop over CPU array and create each lAPIC
  register_timer_device(_apics->lapic_ref(0));
  _apics->lapic(0)->attach_cpu_thread(cpus->cpu(0)->thread_cap());
  vcpu0.register_pt_walker(&_ptw);

  Dbg(Dbg::Guest, Dbg::Info).printf("Starting VMM @ 0x%lx\n", vcpu0->r.ip);

  // TODO If SVM is implemented, we need to branch here for the Vm_state_t
  // to use the correct handle_exit_* function.
  run_vmx(cpus->cpu(0));
}

void
Guest::run_vmx(cxx::Ref_ptr<Cpu_dev> const &cpu_dev)
{
  Vcpu_ptr vcpu = cpu_dev->vcpu();
  Vmx_state *vm = dynamic_cast<Vmx_state *>(vcpu.vm_state());
  assert(vm);
  L4::Cap<L4::Thread> myself;
  trace().printf("Starting vCPU 0x%lx\n", vcpu->r.ip);

  while (1)
    {
      l4_msgtag_t tag = myself->vcpu_resume_commit(myself->vcpu_resume_start());
      auto e = l4_error(tag);

      if (e == 1)
      // Fiasco indicates pending IRQs (IPCs); see fiasco: resume_vcpu()
        {
          if (tag.has_error())
            Dbg().printf("tag has error, but used as ack\n");
          process_pending_ipc(vcpu, l4_utcb());
        }
      else if (e)
        {
          Err().printf("Resume failed with error %ld\n", e);
          vm->dump_state();
          enter_kdebug("FAILURE IN VMM RESUME");
          exit(1);
        }
      else
        {
          int ret = handle_exit_vmx(vcpu);
          if (ret < 0)
            {
              trace().printf("Failure in VMM %i\n", ret);
              vm->dump_state();
              // TODO how can I pass the trace() file?
              cpu_dev->show_state_registers(stderr);
              halt_vm();
            }
          else if (ret == Jump_instr)
            {
              vm->jump_instruction();
            }
        }

      if (vm->interrupts_enabled())
        {
          vm->disable_interrupt_window();
          int irq = current_lapic(vcpu)->next_pending_irq();
          if (irq >= 0)
            {
              if (0)
                trace().printf(
                  "regs: AX 0x%lx, BX 0x%lx, CX 0x%lx, DX 0x%lx, SI 0x%lx, "
                  "DI 0x%lx, IP 0x%lx\n",
                  vcpu->r.ax, vcpu->r.bx, vcpu->r.cx, vcpu->r.dx,
                  vcpu->r.si, vcpu->r.di, vm->ip());

              vm->inject_interrupt(irq);
            }
        }
      else
        vm->enable_interrupt_window();
    }

}

} // namespace

