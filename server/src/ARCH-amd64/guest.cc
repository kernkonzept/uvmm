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
__thread unsigned vmm_current_cpu_id;

namespace {

static inline void cpuid(l4_uint32_t leaf, l4_uint32_t sub,
                         l4_uint32_t *eax, l4_uint32_t *ebx, l4_uint32_t *ecx,
                         l4_uint32_t *edx)
{
  asm volatile("cpuid"
               : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
               : "a"(leaf), "c"(sub));
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
  _event_recorders.init(_cpus->size());
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
  register_msr_device(Vdev::make_device<Mtrr_msr_handler>());
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
  l4_umword_t op_mask = (1ULL << ((1U << op_width) * 8)) - 1;

  if (is_in)
    {
      l4_uint32_t value = ~0U;
      bool ret = handle_io_access_ptr(port, true, op_width, &value);
      if (!ret)
        {
          trace().printf("WARNING: Unhandled IO read port 0x%x/%u\n",
                     port, (1U << op_width) * 8);
          regs->ax = ~0ULL & op_mask;
          return Jump_instr;
        }

      regs->ax = (regs->ax & ~op_mask) | (value & op_mask);
    }
  else
    {
      l4_uint32_t value = regs->ax & op_mask;
      bool ret = handle_io_access_ptr(port, false, op_width, &value);
      if (!ret)
        {
          trace().printf("WARNING: Unhandled IO write port 0x%x/%u <- 0x%x\n",
                         port, (1U << op_width) * 8, value);
          return Jump_instr;
        }
    }

  return Jump_instr;
}

bool
Guest::handle_io_access_ptr(unsigned port, bool is_in,
                            Mem_access::Width op_width, l4_uint32_t *value)
{
  std::unique_lock<std::mutex> lock(_iomap_lock);
  auto f = _iomap.find(Io_region(port));
  if (f == _iomap.end())
    return false;

  port -= f->first.start;
  cxx::Ref_ptr<Io_device> device = f->second;
  lock.unlock();

  if (is_in)
    device->io_in(port, op_width, value);
  else
    device->io_out(port, op_width, *value);

  return true;
}

int
Guest::handle_cpuid(Vcpu_ptr vcpu)
{
  l4_vcpu_regs_t *regs = &vcpu->r;
  unsigned int a,b,c,d;
  auto rax = regs->ax;
  auto rcx = regs->cx;
  Vm_state *vms = vcpu.vm_state();

  if (rax >= 0x40000000 && rax <= 0x4fffffff)
    {
      if (!handle_cpuid_devices(regs, &a, &b, &c, &d))
        a = b = c = d = 0;
    }
  else
    cpuid(rax, rcx, &a, &b, &c, &d);

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
    // fiasco limits to x87, SEE, AVX, AVX512 states
    Xcr0_fiasco_feature_mask = 0xe7,
    Xsave_opt = 1,
    Xsave_c = (1UL << 1),
    Xget_bv = (1UL << 2),
    Xsave_s = (1UL << 3),
    Xfd_bit = (1UL << 4),

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
            // limit reply to what fiasco supports
            a = a & Xcr0_fiasco_feature_mask;

            if (!_xsave_layout.valid)
              {
                trace().printf("\n\n building xsave cache \n\n");

                // build cache
                for (int i = 2; a >> i; ++i)
                  {
                    if (!((a >> i) & 1))
                      continue;

                    l4_uint32_t ax, bx, cx, dx;
                    cpuid(0xd, i, &ax, &bx, &cx, &dx);
                    _xsave_layout.feat[i].size = ax;
                    _xsave_layout.feat[i].offset = bx;
                  }
                _xsave_layout.valid = true;
                // feature offset and size does not change during runtime.
              }

            l4_uint64_t xcr0_guest_enabled = vms->xcr0();
            l4_uint64_t offset = 0;
            int highest_index_feat = 0; // default to x87
            int highest_index_feat_enabled = 0; // default to x87

            // Find the feature and the enabled feature with the highest
            // offset in the Xsave state. This only works in standard format!
            // Compact format not supported, see case 1: below.
            for (int i = 2; i < Xsave_state_area::Num_fields; ++i)
              {
                if (_xsave_layout.feat[i].offset > offset)
                  {
                    offset = _xsave_layout.feat[i].offset;
                    highest_index_feat = i;
                    if (xcr0_guest_enabled & (1 << i))
                      highest_index_feat_enabled = i;
                  }
              }

            if (highest_index_feat == 0)
              {
                // x87 is always on, but we then have only the legacy area.
                // SSE on or off is handled in the legacy area and thus doesn't
                // affect the size computation.
                b = c = 512 + 64; // bytes; legacy area + Xsave header
                d = 0;
              }
            else
              {
                // report possible XSAVE state size
                Xsave_state_area::Size_off feat =
                  _xsave_layout.feat[highest_index_feat];
                c = feat.offset + feat.size;

                // report enabled XSAVE state size
                if (highest_index_feat_enabled == 0)
                  {
                    b = 512 + 64; // bytes; legacy area + Xsave header
                  }
                else
                  {
                    feat = _xsave_layout.feat[highest_index_feat_enabled];
                    b = feat.offset + feat.size;
                  }

                d = 0;
              }

            if (0)
              trace().printf("\nReturn XCR0 guest state: 0x%x:0x%x b=%x c=%x, "
                             "(guest XCR0: 0x%llx) \n\n",
                             d, a, b, c, xcr0_guest_enabled);
            break;
          }

        case 1:
          trace().printf("Filtering out xsave capabilities\n");
          a &= ~(  Xsave_opt
                   | Xsave_c
                   | Xget_bv // with ECX=1
                   | Xsave_s // XSAVES/XRSTORS and IA32_XSS MSR
                   | Xfd_bit
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
Guest::sync_all_other_cores_off() const
{
  // send IPI to all cores to power off
  for (auto cpu : *_cpus.get())
    {
      if (cpu && cpu->cpu_online()
          && cpu->vcpu().get_vcpu_id() != vmm_current_cpu_id)
        {
          cpu->send_stop_event();
        }
    }

  // busy-wait until all other cores are off.
  bool all_stop = true;
  do
    {
      all_stop = true;
      for (auto cpu : *_cpus.get())
        {
          if (cpu && cpu->vcpu().get_vcpu_id() == vmm_current_cpu_id)
            continue;

          if (cpu && cpu->cpu_online())
            {
              all_stop = false;
              break;
            }
        }
    } while (!all_stop);
}

unsigned
Guest::cores_running() const
{
  unsigned online = 0;

  for (auto cpu : *_cpus.get())
    if (cpu && cpu->cpu_online())
      ++online;

  return online;
}

void
Guest::run(cxx::Ref_ptr<Cpu_dev_array> const &cpus)
{
  iomap_dump(Dbg::Info);

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

template <typename VMS>
bool
Guest::state_transition_effects(Cpu_dev::Cpu_state const current,
                                Cpu_dev::Cpu_state const new_state,
                                Gic::Virt_lapic *lapic, VMS *vm,
                                Cpu_dev *cpu)
{
  if (current == new_state && current != Cpu_dev::Halted)
    return false;

  if (current == Cpu_dev::Init && new_state == Cpu_dev::Running)
    {
      lapic->clear_irq_state();
      vm->invalidate_pending_event();
      cpu->hot_reset();
    }
  else if (   (current == Cpu_dev::Running && new_state == Cpu_dev::Halted)
           || (current == Cpu_dev::Halted && new_state == Cpu_dev::Halted))
    {
      if (lapic->is_irq_pending() || lapic->is_nmi_pending())
        return true;
    }

  return false;
}

/// returns false if we continue with VMentry
template <typename VMS>
bool
Guest::new_state_action(Cpu_dev::Cpu_state state, bool halt_req,
                        Cpu_dev *cpu, VMS *vm)
{
  // state behavior
  //  Sleeping -- does not happen here
  //  Stopped -- wait for INIT-IPI
  //  Init -- wait for SIPI
  //  Halt -- wait for IPC
  //  Running -- do event injection & vmentry.

  if (halt_req) // includes state check for halted -> halted; running -> halted
    {
      if (event_injection_t(cpu->vcpu(), vm))
        {
          cpu->set_cpu_state(Cpu_dev::Running);
          vm->resume();
          return false;
        }
      else
        {
          assert(state == Cpu_dev::Halted);
          assert(cpu->get_cpu_state() == Cpu_dev::Halted);
        }
    }

  switch(state)
    {
    case Cpu_dev::Stopped:
      // we cannot recover here, when we stopped the last core.
      if (cores_running() == 0)
        {
          Err().printf("[%3u] Last core stopped. Shutting down\n",
                       cpu->vcpu().get_vcpu_id());
          shutdown(Shutdown);
        }
      // fall-through
    case Cpu_dev::Init:
      cpu->wait_for_ipi();
      break;
    case Cpu_dev::Halted:
      cpu->vcpu().wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
      break;
    case Cpu_dev::Running:
      event_injection_t(cpu->vcpu(), vm);
      return false;
    default:
      // Sleeping is never entered once left and other states don't exist, thus
      // this should not happen. Print the error for debugging and stop vCPU.
      // The guest can reset the CPU with an INIT IPI.
      Err().printf("[%3u] CPU device state %i unknown or invalid. "
                   "Stopping core.\n",
                   cpu->vcpu().get_vcpu_id(), state);
      vm->additional_failure_info(cpu->vcpu().get_vcpu_id());
      cpu->stop();
    }

  return true;
}

template<typename VMS>
void L4_NORETURN
Guest::run_vm_t(Vcpu_ptr vcpu, VMS *vm)
{
  unsigned vcpu_id = vcpu.get_vcpu_id();
  auto cpu = _cpus->cpu(vcpu_id);
  auto *ev_rec = recorder(vcpu_id);
  Gic::Virt_lapic *vapic = lapic(vcpu);

  _clocks[vcpu_id].start_clock_source_thread(vcpu_id, cpu->get_phys_cpu_id());

  L4::Cap<L4::Thread> myself;
  trace().printf("Starting vCPU[%3u] 0x%lx\n", vcpu_id, vcpu->r.ip);

  while (1)
    {
      l4_msgtag_t tag = myself->vcpu_resume_commit(myself->vcpu_resume_start());
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
          vm->additional_failure_info(vcpu_id);
          halt_vm(vcpu);
        }
      else
        {
          int ret = handle_exit(cpu.get(), vm);
          if (ret < 0)
            {
              Err().printf("[%3u]: Failure in VMM %i\n", vcpu_id, ret);
              vcpu.dump_regs_t(vm->ip(), Err());
              vm->additional_failure_info(vcpu_id);
              halt_vm(vcpu);
            }
          else switch (ret)
            {
            case Jump_instr:
              vm->jump_instruction();
              vm->clear_sti_shadow();
              break;
            case Invalid_opcode:
              ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 6);
              break;
            case Stack_fault:
              ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 12, 0);
              break;
            case General_protection:
              ev_rec->make_add_event<Event_exc>(Event_prio::Exception, 13, 0);
              break;
            }
        }

      Cpu_dev::Cpu_state new_state = Cpu_dev::Running;
      bool halt_req = false;
      do
        {
          new_state = cpu->next_state();
          halt_req = state_transition_effects(cpu->get_cpu_state(), new_state,
                                              vapic, vm, cpu.get());

          cpu->set_cpu_state(new_state);
        }
      while (new_state_action(new_state, halt_req, cpu.get(), vm));
    }
}

template<typename VMS>
bool
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
      return true;
    }
  else
    {
      return rec->inject(static_cast<Vm_state *>(vm));
    }
}

} // namespace
