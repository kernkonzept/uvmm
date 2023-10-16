/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 *            Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 */

#include <l4/cxx/static_container>
#include <l4/sys/kdebug.h>
#include <l4/sys/debugger.h>

#include "guest.h"
#include "debug.h"
#include "vm_state_vmx.h"
#include "vm_state_svm.h"
#include "consts.h"
#include "vmx_exit_to_str.h"
#include "msr_devices.h"
#include "acpi.h"
#include "mad.h"
#include "event_recorder.h"
#include "event_record.h"
#include "event_record_lapic.h"

static cxx::Static_container<Vmm::Guest> guest;
Acpi::Acpi_device_hub *Acpi::Acpi_device_hub::_hub;
Acpi::Facs_storage *Acpi::Facs_storage::_facs_storage;

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

// Notification to add a stringified exit reason when Exit_reason_max changes.
static_assert(   sizeof(str_exit_reason) / sizeof(*str_exit_reason)
              == static_cast<unsigned>(Vmx_state::Exit::Exit_reason_max),
              "One stringification exists for each VMX exit reason.");

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

void
Guest::register_io_device(cxx::Ref_ptr<Vmm::Io_device> const &dev,
                          Region_type type,
                          Vdev::Dt_node const &node, size_t index)
{
  l4_uint64_t base, size;
  Dtb::Reg_flags flags;
  int res = node.get_reg_val(index, &base, &size, &flags);
  if (res < 0)
    {
      Err().printf("Failed to read 'reg' from node %s(%lu): %s\n",
                   node.get_name(), index, node.strerror(res));
      L4Re::throw_error(-L4_EINVAL, "Reg value is valid.");
    }

  if (!flags.is_ioport())
    {
      Err().printf("Invalid 'reg' property of node %s(%lu): not an ioport\n",
                   node.get_name(), index);
      L4Re::throw_error(-L4_EINVAL, "Reg property contains an ioport.");
    }

  add_io_device(Vmm::Io_region::ss(base, size, type), dev);
}

void Guest::add_io_device(Io_region const &region,
                          cxx::Ref_ptr<Io_device> const &dev)
{
  std::lock_guard<std::mutex> g(_iomap_lock);

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

void Guest::del_io_device(Io_region const &region)
{
  std::lock_guard<std::mutex> g(_iomap_lock);
  trace().printf("Remove io mapping: [0x%lx, 0x%lx]\n", region.start,
                 region.end);
  assert(_iomap.count(region) == 1);
  _iomap.erase(region);
}

void Guest::register_msr_device(cxx::Ref_ptr<Msr_device> const &dev)
{
  _msr_devices.push_back(dev);
  trace().printf("New MSR device %p\n", dev.get());
}

void
Guest::register_cpuid_device(cxx::Ref_ptr<Cpuid_device> const &dev)
{
  _cpuid_devices.push_back(dev);
  trace().printf("New CPUID device %p\n", dev.get());
}

l4_addr_t
Guest::load_binary(Vm_ram *ram, char const *binary, Ram_free_list *free_list)
{
  l4_addr_t entry;

  Boot::Binary_loader_factory bf;
  bf.load(binary, ram, free_list, &entry);

  _guest_t = bf.type();

  // Reserve Zero-page and cmdline space: One page and 4k for the cmdline.
  // XXX It shall move to prepare_binary_run, when the parameter set of that
  // function is changed.
  free_list->reserve_fixed(Vmm::Guest_addr(L4_PAGESIZE), L4_PAGESIZE + 0x1000);

  return entry;
}

void
Guest::prepare_platform(Vdev::Device_lookup *devs)
{
  _cpus = devs->cpus();
  _icr_handler->register_cpus(_cpus);
  unsigned const max_cpuid = _cpus->max_cpuid();
  _ptw = cxx::make_ref_obj<Pt_walker>(devs->ram(), get_max_physical_address_bit());
  for (unsigned id = 0; id <= max_cpuid; ++id)
    {
      auto cpu = _cpus->cpu(id);
      cpu->powerup_cpu();

      Vcpu_ptr vcpu = cpu->vcpu();
      vcpu->user_task = _task.cap();
      vcpu.set_pt_walker(_ptw.get());

      unsigned vcpu_id = vcpu.get_vcpu_id();
      _apics->register_core(vcpu_id, cpu);
      register_timer_device(_apics->get(vcpu_id)->timer(), vcpu_id);
      _apics->get(vcpu_id)->attach_cpu_thread(cpu->thread_cap());
    }

  register_msr_device(Vdev::make_device<Vcpu_msr_handler>(_cpus.get(),
                      &_event_recorders));
  register_msr_device(
    Vdev::make_device<Vdev::Microcode_revision>(_cpus->vcpu(0)));
}

void
Guest::prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const * /*binary*/, char const *cmd_line,
                          l4_addr_t dt_boot_addr)
{
  auto cpus = devs->cpus();
  Vcpu_ptr vcpu = cpus->vcpu(0);

  if (_guest_t == Boot::Rom)
    {
      vcpu->r.ip = entry;
      return;
    }

  Vm_ram *ram = devs->ram().get();

  Acpi::Bios_tables acpi_tables(devs);
  acpi_tables.write_to_guest();

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
  cpus->cpu(0)->set_protected_mode();

  trace().printf("Zeropage setup: vCPU ip: 0x%lx, si: 0x%lx\n", vcpu->r.ip,
                 vcpu->r.si);
}

int
Guest::handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                        l4_vcpu_regs_t *regs)
{
  l4_umword_t op_mask = (1ULL << ((1 << op_width) * 8)) - 1;

  std::unique_lock<std::mutex> lock(_iomap_lock);
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
  cxx::Ref_ptr<Io_device> device = f->second;
  lock.unlock();

  if (is_in)
    {
      l4_uint32_t out = -1;
      device->io_in(port, op_width, &out);

      regs->ax = (regs->ax & ~op_mask) | (out & op_mask);
    }
  else
    device->io_out(port, op_width, regs->ax & op_mask);

  return Jump_instr;
}

int
Guest::handle_cpuid(l4_vcpu_regs_t *regs)
{
  unsigned int a,b,c,d;
  auto rax = regs->ax;
  auto rcx = regs->cx;

  if (rax >= 0x40000000 && rax <= 0x4fffffff)
    {
      if (!handle_cpuid_devices(regs, &a, &b, &c, &d))
        a = b = c = d = 0;
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
    Ecx_thermal_mon2 = (1UL << 8),
    Ecx_sdbg = (1UL << 11),
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
    Digital_sensor = (1UL << 0),
    Power_limit_notification = (1UL << 4),
    Hwp_feature_mask = (0x3UL << 23) | (0x3fUL << 15) | (0x1f << 7),
    Hdc_feature = (1UL << 13), // HDC MSR support

    // 0x6 ECX
    Performance_energy_bias_preference = (1UL << 3),
    // presence of MSRs IA32_MPERF and IA32_APERF
    Hardware_coordination_feedback_capability = 1UL,

    // 0x7 EBX
    Tsc_adjust = (1UL << 1),
    Invpcid_bit = (1UL << 10),
    Intel_rdtm_bit = (1UL << 12),
    Intel_rdta_bit = (1UL << 15),
    Processor_trace = (1UL << 25),
    // 0x7 ECX
    Waitpkg_bit = (1UL << 5),
    La57_bit = (1UL << 16),
    Rdpid_bit = (1UL << 22),
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

    // 0x8000'0001 ECX
    PerfCtrExtCore_bit = (1UL << 23), // AMD specific, Intel reserved
    PerfCtrExtNB_bit = (1UL << 24),   // AMD specific, Intel reserved
    PerfTsc_bit = (1UL << 27),        // AMD specific, Intel reserved
    PerfCtrExtLLC_bit = (1UL << 28),  // AMD specific, Intel reserved
    Amd_perfctr_mask = PerfCtrExtCore_bit | PerfCtrExtNB_bit | PerfTsc_bit
                       | PerfCtrExtLLC_bit, // AMD specific, Intel reserved

    // 0x8000'0001 EDX
    Rdtscp_bit = (1UL << 27),
  };

  switch (rax)
    {
    case 0x1:
      // hide some CPU features
      c &= ~(  Ecx_monitor_bit
             | Ecx_vmx_bit
             | Ecx_smx_bit
             | Ecx_thermal_mon2
             | Ecx_speed_step_tech_bit
             | Ecx_sdbg
             | Ecx_pcid_bit
            );
      c |= Ecx_hypervisor_bit;

      d &= ~(Edx_mca | Edx_acpi_bit);
      break;

    case 0x6:
      a &= ~(Digital_sensor | Power_limit_notification | Hwp_feature_mask
             | Hdc_feature);
      // filter IA32_ENERGEY_PERF_BIAS
      c &= ~(Performance_energy_bias_preference
             | Hardware_coordination_feedback_capability);
      break;

    case 0x7:
      if (!rcx)
        {
          b &= ~(Processor_trace | Invpcid_bit | Intel_rdtm_bit | Intel_rdta_bit
                 | Tsc_adjust);
          c &= ~(Waitpkg_bit | La57_bit | Rdpid_bit);
          d &= ~(Ibrs_ibpb_bit | Stibp_bit | Ssbd_bit
                 | Arch_capabilities_supported_bit);
        }
      break;

    case 0xa:
      // We do not support any performance monitoring features. Report zero in
      // all registers.
      a = b = c = d = 0;
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

    case 0xf:
      // Intel RDT Monitoring not supported, sub-leaf 0 and 1 report zero.
      a = b = c = d = 0;
      break;

    case 0x10:
      // Intel RDT Allocation not supported, sub-leaf 0 and 1 report zero.
      a = b = c = d = 0;
      break;

    case 0x80000001:
      {
        c &= ~(Amd_perfctr_mask);
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

  // Handle KVM queries gracefully
  if (regs->ax == 9) // KVM_HC_CLOCK_PAIRING
    {
      regs->ax = -1000; // KVM_ENOSYS
      return Jump_instr;
    }

  Err().printf("Unknown VMCALL 0x%lx at 0x%lx\n", regs->ax, regs->ip);
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

bool
Guest::handle_cpuid_devices(l4_vcpu_regs_t const *regs, unsigned *a,
                            unsigned *b, unsigned *c, unsigned *d)
{
  for (auto &dev : _cpuid_devices)
    {
      if (dev->handle_cpuid(regs, a, b, c, d))
        return true;
    }
  return false;
}

void
Guest::run(cxx::Ref_ptr<Cpu_dev_array> const &cpus)
{
  info().printf("Starting VMM @ 0x%lx\n", cpus->vcpu(0)->r.ip);

  // Additional vCPUs are initialized to run startup on the first reschedule.
  cpus->cpu(0)->startup();
}

void L4_NORETURN
Guest::run_vm(Vcpu_ptr vcpu)
{
  Vm_state *vm = vcpu.vm_state();
  assert(vm);

  if (vm->type() == Vm_state::Type::Vmx)
    {
      Vmx_state *vms = dynamic_cast<Vmx_state *>(vm);
      assert(vms);
      run_vm_t(vcpu, vms);
    }
  else /* if (vm->type() == Vm_state::Type::Svm) */
    {
      Svm_state *vms = dynamic_cast<Svm_state *>(vm);
      assert(vms);
      run_vm_t(vcpu, vms);
    }
}

template<typename VMS>
void L4_NORETURN
Guest::run_vm_t(Vcpu_ptr vcpu, VMS *vm)
{
  unsigned vcpu_id = vcpu.get_vcpu_id();
  auto cpu = _cpus->cpu(vcpu_id);
  Gic::Virt_lapic *vapic = lapic(vcpu);

  _clocks[vcpu_id].start_clock_source_thread(vcpu_id, cpu->get_phys_cpu_id());

  L4::Cap<L4::Thread> myself;
  trace().printf("Starting vCPU[%3u] 0x%lx\n", vcpu_id, vcpu->r.ip);

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
            Dbg().printf("[%3u]: tag has error, but used as ack\n", vcpu_id);
          vcpu.process_pending_ipc(l4_utcb());
        }
      else if (e)
        {
          Err().printf("[%3u]: Entering VM failed with error %ld\n",
                       vcpu_id, e);
          vm->additional_failure_info();
          halt_vm(vcpu);
        }
      else
        {
          int ret = handle_exit(vcpu, vm);
          if (ret < 0)
            {
              trace().printf("[%3u]: Failure in VMM %i\n", vcpu_id, ret);
              trace().printf("[%3u]: regs: AX 0x%lx, BX 0x%lx, CX 0x%lx, "
                             "DX 0x%lx, SI 0x%lx, DI 0x%lx, IP 0x%lx\n",
                             vcpu_id, vcpu->r.ax, vcpu->r.bx, vcpu->r.cx,
                             vcpu->r.dx, vcpu->r.si, vcpu->r.di, vm->ip());
              halt_vm(vcpu);
            }
          else if (ret == Jump_instr)
            {
              vm->jump_instruction();
              vm->clear_sti_shadow();
            }
        }

      // Handle stopped CPUs.
      // In the case of Halt, the CPU has to be stopped until a device
      // interrupt happens.
      // In the case of the INIT state, the CPU has to be stopped until a
      // startup IPI happens. INIT state is entered when an INIT IPI happens.
      // - An INIT IPI can occur any time (e.g. when the CPU is already in
      //   Halt).
      // - A device interrupt can happen anytime. We must make sure that none
      //   happened before we enter wait_for_ipc().
      // - Therefore order is important!
      if (cpu->get_cpu_state() == Vmm::Cpu_dev::Cpu_state::Init
          || vm->is_halted())
        {
          do
            {
              // if we are in INIT state we must wait until a startup ipi
              // starts us up again
              if (cpu->get_cpu_state() == Vmm::Cpu_dev::Cpu_state::Init)
                {
                  while (cpu->get_cpu_state() != Vmm::Cpu_dev::Cpu_state::Running)
                    vcpu.wait_for_ipc(l4_utcb(), L4_IPC_NEVER);

                  // The CPU is not supposed to accept interrupts while in
                  // INIT mode. We emulate that by clearing all interrupts
                  // that happened while CPU was stopped.
                  vapic->clear_irq_state();
                  break;
                }

              // if an interrupt happened, the CPU must return from Halt state
              // We cannot be sure that the pending interrupt is also
              // injectable, thus we set the activity state unconditionally.
              if (vm->is_halted()
                  && (vapic->is_irq_pending() || vapic->is_nmi_pending()))
                {
                  vm->resume();
                  break;
                }

              // give up CPU for other tasks
              vcpu.wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
            }
          while (1);
        }

      event_injection_t(vcpu, vm);
    }
}

template<typename VMS>
void
Guest::event_injection_t(Vcpu_ptr vcpu, VMS *vm)
{
  Event_recorder *rec = recorder(vcpu.get_vcpu_id());
  // XXX Record pending events in other subsystems in the event recorder
  Gic::Virt_lapic *apic = lapic(vcpu);
  if (!rec->has_nmi() && apic->next_pending_nmi())
    rec->make_add_event<Event_nmi>(apic);

  if (!rec->has_irq() && apic->is_irq_pending())
    {
      // Event_record::ev_num not used on IRQ, as we query the LAPIC for the
      // exact value.
      rec->make_add_event<Event_irq>(apic);
    }


  // TODO reenqueue what we haven't injected.
  Injection_event pending_event = vm->pending_event_injection();

  if (pending_event.valid())
    {
      vm->inject_event(pending_event);
    }
  else
    {
      rec->inject(static_cast<Vm_state *>(vm));
    }
}

} // namespace
