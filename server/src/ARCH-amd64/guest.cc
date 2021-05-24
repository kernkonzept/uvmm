/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/static_container>
#include <l4/sys/kdebug.h>
#include <l4/sys/debugger.h>

#include "binary_loader.h"
#include "guest.h"
#include "debug.h"
#include "vm_state_vmx.h"
#include "consts.h"
#include "vmx_exit_to_str.h"
#include "msr_devices.h"
#include "acpi.h"

static cxx::Static_container<Vmm::Guest> guest;
Acpi::Acpi_device_hub *Acpi::Acpi_device_hub::_hub;

namespace {

static inline void
fxrstor64(char *addr)
{
  __asm__ __volatile__("fxrstor64 %0"
                       :
                       : "m" (*addr)
                       : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
                         "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
                         "xmm12", "xmm13", "xmm14", "xmm15", "mm0", "mm1",
                         "mm2", "mm3", "mm4", "mm5", "mm6", "mm7");
}

static inline void
fxsave64(char *addr)
{
  __asm__ __volatile__("fxsave64 %0"
                       : "=m" (*addr));
}

}

namespace Vmm {

Guest *
Guest::create_instance()
{
  trace().printf("creating instance\n");
  guest.construct();
  return guest;
}

Guest *
Guest::get_instance()
{
  return guest;
}

void Guest::register_io_device(Io_region const &region,
                               cxx::Ref_ptr<Io_device> const &dev)
{
  // Check for overlapping regions!
  if (_iomap.count(region) != 0)
    {
      info().printf("IO map overlap: [0x%lx, 0x%lx]\n", region.start,
                    region.end);
      L4Re::chksys(-L4_EINVAL, "IO map entry overlapping.");
    }

  _iomap[region] = dev;

  trace().printf("New io mapping: %p @ [0x%lx, 0x%lx]\n", dev.get(),
                 region.start, region.end);
}

void Guest::register_msr_device(cxx::Ref_ptr<Msr_device> const &dev)
{
  _msr_devices.push_back(dev);
  trace().printf("New MSR device %p\n", dev.get());
}

l4_addr_t
Guest::load_linux_kernel(Vm_ram *ram, char const *kernel,
                         Ram_free_list *free_list)
{
  l4_addr_t entry;
  Boot::Binary_ds image(kernel);

  if (image.is_elf_binary())
    {
      entry = image.load_as_elf(ram, free_list);
      _guest_t = Binary_type::Elf;
    }
  else
    {
      l4_uint8_t num_setup_sects =
        *((char *)image.get_header() + Bp_setup_sects);
      trace().printf("number of setup sections found: 0x%x\n", num_setup_sects);

      // 512 is the size of a segment
      l4_addr_t setup_sects_size = (num_setup_sects + 1) * 512;

      if (Linux_kernel_start_addr < setup_sects_size)
        L4Re::chksys(-L4_EINVAL,
                     "Supplied kernel image contains an invalid number "
                     " of setup sections (zeropage).");

      entry = Linux_kernel_start_addr - setup_sects_size;
      trace().printf("size of setup sections: 0x%lx\n", setup_sects_size);
      trace().printf("loading binary at: 0x%lx\n", entry);

      // load the binary starting after the boot_params
      auto z = image.load_as_raw(ram, ram->boot2guest_phys(entry), free_list);
      trace().printf("Loaded kernel image as raw to 0x%lx\n", z);
      trace().printf("load kernel as raw entry to 0x%lx\n",
                     ram->guest_phys2boot(Vmm::Guest_addr(Linux_kernel_start_addr)));
      _guest_t = Binary_type::Linux;
    }

  // Reserve Zero-page and cmdline space: One page and 4k for the cmdline.
  // XXX It shall move to prepare_linux_run, when the parameter set of that
  // function is changed.
  free_list->reserve_fixed(Vmm::Guest_addr(L4_PAGESIZE), L4_PAGESIZE + 0x1000);

  return entry;
}

void
Guest::prepare_platform(Vdev::Device_lookup *devs)
{
  auto cpus = devs->cpus();
  _icr_handler->register_cpus(cpus);
  unsigned const max_cpuid = cpus->max_cpuid();
  _ptw = cxx::make_ref_obj<Pt_walker>(devs->ram(), get_max_physical_address_bit());
  for (unsigned id = 0; id <= max_cpuid; ++id)
    {
      auto cpu = cpus->cpu(id);
      cpu->powerup_cpu();

      Vcpu_ptr vcpu = cpu->vcpu();
      vcpu->user_task = _task.cap();
      vcpu.set_pt_walker(_ptw.get());

      unsigned vcpu_id = vcpu.get_vcpu_id();
      _apics->register_core(vcpu_id);
      register_timer_device(_apics->get(vcpu_id), vcpu_id);
      _apics->get(vcpu_id)->attach_cpu_thread(cpu->thread_cap());

      auto phys_cpu_id = cpu->get_phys_cpu_id();
      _clocks[id].start_timer_thread(id, phys_cpu_id);
    }

  register_msr_device(Vdev::make_device<Vcpu_msr_handler>(cpus.get()));
  register_msr_device(
    Vdev::make_device<Vdev::Microcode_revision>(cpus->vcpu(0)));

  Acpi::Tables acpi_tables(devs->ram());
  acpi_tables.write_to_guest(cpus->max_cpuid() + 1);
}

void Guest::prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry, Vm_ram *ram,
                              char const * /* kernel */, char const *cmd_line,
                              l4_addr_t dt_boot_addr)
{
  // use second memory page as zeropage location
  Zeropage zpage(Vmm::Guest_addr(L4_PAGESIZE), entry);

  if (dt_boot_addr)
    {
      // read initrd addr and size from device tree
      Vmm::Guest_addr dt_addr = ram->boot2guest_phys(dt_boot_addr);
      Dtb::Fdt fdt(ram->guest2host<void *>(dt_addr));
      auto dt = Vdev::Device_tree(&fdt);
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
        warn().printf("No ramdisk found in device tree.\n");

      zpage.add_dtb(dt_boot_addr, dt.size());
    }

  if (cmd_line)
    zpage.add_cmdline(cmd_line);

  zpage.cfg_e820(ram);
  // write zeropage to VM ram
  zpage.write(ram, _guest_t);

  vcpu->r.ip = zpage.entry(ram);
  vcpu->r.si = zpage.addr().get();

  trace().printf("Zeropage setup: vCPU ip: 0x%lx, si: 0x%lx\n", vcpu->r.ip,
                 vcpu->r.si);
}

int
Guest::handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                        l4_vcpu_regs_t *regs)
{
  l4_umword_t op_mask = (1ULL << ((1 << op_width) * 8)) - 1;

  auto f = _iomap.find(Io_region(port));
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
  auto rcx = regs->cx;

  if (rax >= 0x40000000 && rax < 0x40010000)
    {
      switch (rax)
        {
        case 0x40000000:
          a = 0x40000001;   // max CPUID leaf in the 0x4000'0000 range.
          b = 0x4b4d564b;   // "KVMK"
          c = 0x564b4d56;   // "VMKV"
          d = 0x4d;         // "M\0\0\0"
          break;

        case 0x40000001:
          enum Cpuid_kvm_constants
          {
            Kvm_feature_clocksource = 1UL, // clock at msr 0x11 & 0x12
            Kvm_feature_clocksource2 = 1UL << 3, // clock at msrs 0x4b564d00 & 01;
          };
          a = Kvm_feature_clocksource2;
          d = 0;
          b = c = 0;
          break;

        default:
          a = b = c = d = 0;
        }
    }
  else
    asm("cpuid"
      : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
      : "0"(rax), "2"(rcx));

  if (0)
    trace().printf("CPUID as read 0x%lx/0x%lx: a: 0x%x, b: 0x%x, c: 0x%x, d: 0x%x\n",
                   rax, rcx, a, b, c, d);

  enum : unsigned long
  {
    // 0x1
    Ecx_monitor_bit = (1UL << 3),
    Ecx_vmx_bit = (1UL << 5),
    Ecx_smx_bit = (1UL << 6),
    Ecx_speed_step_tech_bit = (1UL << 7),
    Ecx_pcid_bit = (1UL << 17),
    Ecx_x2apic_bit = (1UL << 21),
    Ecx_xsave_bit = (1UL << 26),
    // used to indicate the hypervisor presence to linux -- no hardware bit.
    Ecx_hypervisor_bit = (1UL << 31),

    Edx_mtrr_bit = (1UL << 12),
    Edx_mca = (1UL << 14),
    Edx_pat = (1UL << 16),
    Edx_acpi_bit = (1UL << 22),

    // 0x6 EAX
    Power_limit_notification = (1UL << 4),
    Hwp_feature_mask = (0x1f << 7),
    // 0x6 ECX
    Performance_energy_bias_preference = (1UL << 3),

    // 0x7 EBX
    Tsc_adjust = (1UL << 1),
    Invpcid_bit = (1UL << 10),
    // 0x7 EDX
    Ibrs_ibpb_bit = (1UL << 26),
    Stibp_bit = (1UL << 27),
    Arch_capabilities_supported_bit = (1UL << 29), // IA32_ARCH_CAPABILITIES MSR
    Ssbd_bit = (1UL << 31),

    // AMD speculation control.
    // 0x8000'0008 EBX
    // Whitepaper AMD64 Technology: Indirect Branch Control Extension,
    // revision 4.10.18
    Amd_ibpb_bit = (1UL << 12),
    Amd_ibrs_bit = (1UL << 14),
    Amd_stibp_bit = (1UL << 15),
    // Whitepaper AMD64 Technology: Speculative Store Bypass Disable, 5.21.18
    Amd_ssbd_bit = (1UL << 24),


    // 0xd
    Xsave_opt = 1,
    Xsave_c = (1UL << 1),
    Xget_bv = (1UL << 2),
    Xsave_s = (1UL << 3),

    // 0x8000'0001
    Rdtscp_bit = (1UL << 27),
  };

  switch (rax)
    {
    case 0x1:
      // hide some CPU features
      c &= ~(  Ecx_monitor_bit
             | Ecx_vmx_bit
             | Ecx_smx_bit
             | Ecx_speed_step_tech_bit
             | Ecx_pcid_bit
            );
      c |= Ecx_hypervisor_bit;

      d &= ~(Edx_mtrr_bit | Edx_mca | Edx_pat | Edx_acpi_bit);
      break;

    case 0x6:
      a &= ~(Power_limit_notification | Hwp_feature_mask);
      // filter IA32_ENERGEY_PERF_BIAS
      c &= ~(Performance_energy_bias_preference);
      break;

    case 0x7:
      if (!rcx)
        {
          b &= ~(Invpcid_bit | Tsc_adjust);
          d &= ~(Ibrs_ibpb_bit | Stibp_bit | Ssbd_bit
                 | Arch_capabilities_supported_bit);
        }
      break;

    case 0xa:
      a &= ~0xffULL;  // disable perfmon
      break;

    case 0xd:
      switch(rcx)
        {
        case 0:
          {
            // Check the host-enabled XCR0 bits and report these to the guest,
            // instead of the physical hardware features.
            // XXX If we report other than the host-enabled XCR0 bits, we need
            // to adapt the size returned in ECX!
            l4_uint32_t ax = 0, dx = 0;
            asm volatile ("xgetbv" : "=a"(ax), "=d"(dx) : "c"(0));
            trace().printf("Get XCR0 host state: 0x%x:0x%x\n", dx, ax);

            a = ax;
            break;
          }

        case 1:
          trace().printf("Filtering out xsave capabilities\n");
          a &= ~(  Xsave_opt
                   | Xsave_c
                   | Xget_bv // with ECX=1
                   | Xsave_s   // XSAVES/XRSTORS and IA32_XSS MSR
                );
          b = 0; // Size of the state of the enabled feature bits.
          break;

        default: break;
        }
      break;

    case 0x80000001:
      {
        d &= ~( Rdtscp_bit );
        break;
      }

    case 0x80000008:
      {
        // According to the Linux source code at arch/x86/kernel/cpu/common.c,
        // "[...] a hypervisor might have set the individual AMD bits even on
        // Intel CPUs, for finer-grained selection of what's available."
        // Thus filter AMD bits for the case of nested virtualization.
        b &= ~(Amd_ibpb_bit | Amd_ibrs_bit | Amd_stibp_bit | Amd_ssbd_bit);
        break;
      }
    }

  if (0)
    trace().printf("CPUID as modified: a: 0x%x, b: 0x%x, c: 0x%x, d: 0x%x\n",
                   a, b, c, d);

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

  // NOTE: If the hypervisor bit is enabled in CPUID.01 there can be other VMCALL
  // numbers defined for KVM, e.g. 0x9 for PTP_KVM.
  Err().printf("Unknown VMCALL 0x%lx\n", regs->ax);
  return -L4_ENOSYS;
}

bool
Guest::msr_devices_rwmsr(l4_vcpu_regs_t *regs, bool write, unsigned vcpu_no)
{
  auto msr = regs->cx;

  for (auto &dev : _msr_devices)
    {
      if (write)
        {
          l4_uint64_t value = (l4_uint64_t(regs->ax) & 0xFFFFFFFF)
                              | (l4_uint64_t(regs->dx) << 32);
          if (dev->write_msr(msr, value, vcpu_no))
            return true;
        }
      else
        {
          l4_uint64_t result = 0;
          if (dev->read_msr(msr, &result, vcpu_no))
            {
              regs->ax = (l4_uint32_t)result;
              regs->dx = (l4_uint32_t)(result >> 32);
              return true;
            }
        }
    }

  return false;
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
    trace().printf("Exit at guest IP 0x%lx with 0x%llx (Qual: 0x%llx)\n",
                   vms->ip(),
                   vms->vmx_read(VMCS_EXIT_REASON),
                   vms->vmx_read(VMCS_EXIT_QUALIFICATION));

  switch (reason)
    {
    case Exit::Cpuid: return handle_cpuid(regs);

    case Exit::Exec_vmcall: return handle_vm_call(regs);

    case Exit::Io_access:
      {
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);
        unsigned qwidth = qual & 7;
        bool is_read = qual & 8;
        unsigned port = (qual >> 16) & 0xFFFFU;

        Dbg(Dbg::Dev, Dbg::Trace)
          .printf("VM exit: IO port access with exit qualification 0x%llx: "
                  "%s port 0x%x\n",
                  qual, is_read ? "read" : "write", port);

        if (port == 0xcfb)
          Dbg(Dbg::Dev, Dbg::Trace)
            .printf(" 0xcfb access from ip: %lx\n", vms->ip());

        Mem_access::Width wd = Mem_access::Wd32;
        switch(qwidth)
          {
          // only 0,1,3 are valid values in the exit qualification.
          case 0: wd = Mem_access::Wd8; break;
          case 1: wd = Mem_access::Wd16; break;
          case 3: wd = Mem_access::Wd32; break;
          }

        return handle_io_access(port, is_read, wd, regs);
      }

    // Ept_violation needs to be checked here, as handle_mmio needs a vCPU ptr,
    // which cannot be passed to Vm_state/Vmx_state due to dependency reasons.
    case Exit::Ept_violation:
      {
        auto guest_phys_addr =
          vms->vmx_read(VMCS_GUEST_PHYSICAL_ADDRESS);
        auto qual = vms->vmx_read(VMCS_EXIT_QUALIFICATION);

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
                       vms->vmx_read(VMCS_GUEST_LINEAR_ADDRESS));
        return -L4_EINVAL;
      }

    // VMX specific exits
    case Exit::Exception_or_nmi:
    case Exit::External_int:
      return vms->handle_exception_nmi_ext_int();

    case Exit::Interrupt_window:
      return L4_EOK;

    case Exit::Exec_halt:
      trace().printf("HALT 0x%llx!\n", vms->vmx_read(VMCS_GUEST_RIP));
      vms->vmx_write(VMCS_GUEST_ACTIVITY_STATE, 1);

      if (!lapic(vcpu)->is_irq_pending())
        wait_for_ipc(l4_utcb(), L4_IPC_NEVER);

      vms->unhalt();
      return L4_EOK;

    case Exit::Cr_access:
      return vms->handle_cr_access(regs);

    case Exit::Exec_rdmsr:
      if (!msr_devices_rwmsr(regs, false, vcpu.get_vcpu_id()))
        {
          warn().printf("Reading unsupported MSR 0x%lx\n", regs->cx);
          regs->ax = 0;
          regs->dx = 0;
          vms->inject_hw_exception(13, Vmx_state::Push_error_code, 0);
          return L4_EOK;
        }

      return Jump_instr;

    case Exit::Exec_wrmsr:
      if (msr_devices_rwmsr(regs, true, vcpu.get_vcpu_id()))
        return Jump_instr;
      else
        {
          warn().printf("Writing unsupported MSR 0x%lx\n", regs->cx);
          vms->inject_hw_exception(13, Vmx_state::Push_error_code, 0);
          return L4_EOK;
        }

    case Exit::Virtualized_eoi:
      Dbg().printf("INFO: EOI virtualized for vector 0x%llx\n",
                   vms->vmx_read(VMCS_EXIT_QUALIFICATION));
      // Trap like exit: IP already on next instruction
      return L4_EOK;

    case Exit::Exec_xsetbv:
      if (regs->cx == 0)
        {
          l4_uint64_t value = (l4_uint64_t(regs->ax) & 0xFFFFFFFF)
                              | (l4_uint64_t(regs->dx) << 32);
          vms->vmx_write(L4_VM_VMX_VMCS_XCR0, value);
          trace().printf("Setting xcr0 to 0x%llx\n", value);
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
                   vms->ip(), vms->vmx_read(VMCS_EXIT_REASON),
                   vms->vmx_read(VMCS_EXIT_QUALIFICATION));
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
  info().printf("Starting VMM @ 0x%lx\n", cpus->vcpu(0)->r.ip);

  // Additional vCPUs are initialized to run startup on the first reschedule.
  cpus->cpu(0)->startup();
}

void L4_NORETURN
Guest::run_vmx(Vcpu_ptr vcpu)
{
  Vmx_state *vm = dynamic_cast<Vmx_state *>(vcpu.vm_state());
  assert(vm);

  L4::Cap<L4::Thread> myself;
  trace().printf("Starting vCPU 0x%lx\n", vcpu->r.ip);

  // Architecturally defined as 512 byte buffer but processor does not write
  // bytes 464:511.
  char fpu_state[464] __attribute__((aligned(16)));
  fxsave64(fpu_state);

  while (1)
    {
      // We do not save/restore the AVX state in the assumption that gcc does
      // not generate such code (yet).
      fxrstor64(fpu_state);
      l4_msgtag_t tag = myself->vcpu_resume_commit(myself->vcpu_resume_start());
      fxsave64(fpu_state);
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
          enter_kdebug("FAILURE IN VMM RESUME");
          halt_vm();
        }
      else
        {
          int ret = handle_exit_vmx(vcpu);
          if (ret < 0)
            {
              trace().printf("Failure in VMM %i\n", ret);
              halt_vm();
            }
          else if (ret == Jump_instr)
            {
              vm->jump_instruction();
            }
        }

      if (vm->can_inject_interrupt())
        {
          vm->disable_interrupt_window();
          int irq = lapic(vcpu)->next_pending_irq();
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
