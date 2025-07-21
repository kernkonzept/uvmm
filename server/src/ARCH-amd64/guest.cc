/*
 * Copyright (C) 2017-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 *            Georg Kotheimer <georg.kotheimer@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
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
#include "cpuid.h"
#include "openbsd_bootparams.h"

static cxx::Static_container<Vmm::Guest> guest;
Acpi::Acpi_device_hub *Acpi::Acpi_device_hub::_hub;
Acpi::Facs_storage *Acpi::Facs_storage::_facs_storage;
Acpi::Madt_int_override_storage *Acpi::Madt_int_override_storage::_self;
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
  int res = node.get_reg_io(index, &base, &size);
  if (res == -node.ERR_REG_INVALID)
    {
      Err().printf("Invalid 'reg' property of node %s(%lu): not an ioport\n",
                   node.get_name(), index);
      L4Re::throw_error(-L4_EINVAL, "Reg property contains an ioport.");
    }
  else if (res < 0)
    {
      Err().printf("Failed to read 'reg' from node %s(%lu): %s\n",
                   node.get_name(), index, node.strerror(res));
      L4Re::throw_error(-L4_EINVAL, "Reg value is valid.");
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

bool Guest::i8042_present()
{
  std::unique_lock<std::mutex> lock(_iomap_lock);

  auto i = _iomap.find(Io_region(0x60));
  if (i == _iomap.end())
    return false;

  i = _iomap.find(Io_region(0x64));
  if (i == _iomap.end())
    return false;

  return true;
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

  _guest_size = bf.get_size();
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
                          char const * binary, char const *cmd_line,
                          l4_addr_t dt_boot_addr)
{
  switch(guest_type())
    {
    case Boot::Binary_type::Rom:
      {
        auto cpus = devs->cpus();
        Vcpu_ptr vcpu = cpus->vcpu(0);

        vcpu->r.ip = entry;
        break;
      }
    case Boot::Binary_type::Linux:
    case Boot::Binary_type::Elf:
      prepare_linux_binary_run(devs, entry, binary, cmd_line, dt_boot_addr);
      break;
    case Boot::Binary_type::OpenBSD:
      prepare_openbsd_binary_run(devs, entry, binary, cmd_line, dt_boot_addr);
      break;
    default:
      Err().printf("Unsupported guest binary type %i\n", _guest_t);
      L4Re::throw_error(-L4_ENOSYS, "Unsupported binray type");
    }
}

void
Guest::prepare_openbsd_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                                  char const * /*binary*/,
                                  char const * /*cmd_line*/,
                                  l4_addr_t /*dt_boot_addr*/)
{
  Acpi::Bios_tables acpi_tables(devs);
  acpi_tables.write_to_guest();

  // Legacy kernels have entry set to 0xffff'ffff'8100'1000. Mask off the
  // high bits to get the expected 0x100'1000 for the
  // legacy kernel entry point
  // Cloned from OpenBSD's sys/arch/amd64/stand/libsa/exec_i386.c
  l4_addr_t masked_entry = entry & 0xfff'ffff;

  // Prepare stack for the kernel parameters
  Vmm::Openbsd::Boot_params params(Vmm::Guest_addr(
                                     Vmm::Openbsd::Boot_params::Phys_mem_addr),
                                   masked_entry, _guest_size);

  // Write params
  params.write(devs->ram().get());

  auto cpus = devs->cpus();
  Vcpu_ptr vcpu = cpus->vcpu(0);

  vcpu->r.ip = masked_entry;
  vcpu->r.sp = Vmm::Openbsd::Boot_params::Phys_mem_addr;
  cpus->cpu(0)->set_protected_mode();
}

void
Guest::prepare_linux_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                                char const * /*binary*/, char const *cmd_line,
                                l4_addr_t dt_boot_addr)
{
  auto cpus = devs->cpus();
  Vcpu_ptr vcpu = cpus->vcpu(0);
  Vm_ram *ram = devs->ram().get();

  Acpi::Bios_tables acpi_tables(devs);
  acpi_tables.write_to_guest();

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
  vcpu->r.sp = 0UL;
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
  unsigned id = vcpu.get_vcpu_id();
  l4_uint32_t a,b,c,d;
  l4_uint64_t rax = regs->ax;
  l4_uint64_t rcx = regs->cx;
  Vm_state *vms = vcpu.vm_state();

  auto set_regs = [regs] (l4_uint32_t a, l4_uint32_t b,
                          l4_uint32_t c, l4_uint32_t d)
  {
    regs->ax = a;
    regs->bx = b;
    regs->cx = c;
    regs->dx = d;
    return Jump_instr;
  };

  // handle emulated cpuid branches
  if (rax >= 0x4000'0000 && rax <= 0x4fff'ffff)
    {
      if (!handle_cpuid_devices(regs, &a, &b, &c, &d))
        // if there is no handler, return 0
        a = b = c = d = 0;
      return set_regs(a, b, c, d);
    }

  cpuid(rax, rcx, &a, &b, &c, &d);

  if (0)
    trace().printf("[%3u] CPUID as read 0x%llx/0x%llx: a: 0x%x, b: 0x%x, c: 0x%x, d: 0x%x\n",
                   id, rax, rcx, a, b, c, d);

  enum : unsigned long
  {
    // Processor Extended State Enumeration Leaf, 0xd
    // fiasco limits to x87, SSE, AVX, AVX512 states
    Xcr0_fiasco_feature_mask = 0xe7,
    Xsave_opt = 1,
    Xsave_c = (1UL << 1),
    Xget_bv = (1UL << 2),
    Xsave_s = (1UL << 3),
    Xfd_bit = (1UL << 4),
  };

  if (   (rax > Cpuid_max_basic_info_leaf && rax < 0x8000'0000)
      || (rax > Cpuid_max_ext_info_leaf))
    {
      info().printf("[%3u] CPUID leaf 0x%llx not supported\n", id, rax);
      return set_regs(0, 0, 0, 0);
    }

  switch (rax)
    {
    case 0x0:
      a = a < Cpuid_max_basic_info_leaf ? a : Cpuid_max_basic_info_leaf;
      break;
    case 0x1:
      {
        // Emulate Initial APIC ID
        b &= 0x00ffffff;
        if (id < 0x100)
          b |= id << 24;

        cpuid_reg_apply(&c, Cpuid_1_ecx_supported, Cpuid_1_ecx_mandatory);
        cpuid_reg_apply(&d, Cpuid_1_edx_supported);
        break;
      }

    case 0x2:
      [[fallthrough]];
    case 0x3:
      [[fallthrough]];
    case 0x4:
      break;

    case 0x5:
      // monitor/mwait. Not supported.
      a = b = c = d = 0;
      break;

    case 0x6:
      // thermal and power management
      cpuid_reg_apply(&a, Cpuid_6_eax_supported);
      b = c = d = 0;
      break;

    case 0x7:
      if (!rcx)
        {
          a = Cpuid_7_0_eax_leafs;
          cpuid_reg_apply(&b, Cpuid_7_0_ebx_supported);
          cpuid_reg_apply(&c, Cpuid_7_0_ecx_supported);
          cpuid_reg_apply(&d, Cpuid_7_0_edx_supported);
        }
      else
        a = b = c = d = 0;
      break;

    case 0x9:
      // direct cache access information. Not supported.
      a = b = c = d = 0;
      break;

    case 0xa:
      // Performance monitoring features. Not supported.
      a = b = c = d = 0;
      break;

    case 0xb: // Extended Topology Enumeration Leaf
    case 0x1f: // v2 Extended Topology Enumeration
      if (rcx != 0)
        a = b = c = 0;
      // the Local APIC ID of ACPI_MADT_TYPE_LOCAL_APIC for all sub-leafs
      d = id;
      // TODO: Emulate the other registers according to the intended virtual CPU
      //       topology. Also consider ECX>=0 as input.
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
                trace().printf("\n\n [%3u] building xsave cache \n\n", id);

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
              trace().printf("\n[%3u] Return XCR0 guest state: 0x%x:0x%x b=%x c=%x, "
                             "(guest XCR0: 0x%llx) \n\n",
                             id, d, a, b, c, xcr0_guest_enabled);
            break;
          }

        case 1:
          trace().printf("[%3u] Filtering out xsave capabilities\n", id);
          a &= ~(  Xsave_opt
                   | Xsave_c
                   | Xget_bv // with ECX=1
                   | Xsave_s // XSAVES/XRSTORS and IA32_XSS MSR
                   | Xfd_bit
                );
          b = 0; // Size of the state of the enabled feature bits.
          break;

        default:
          break;
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

    case 0x12:
      // SGX information. Not supported.
      a = b = c = d = 0;
      break;

    case 0x14:
      // Intel Processor Trace. Not supported.
      a = b = c = d = 0;
      break;

    case 0x15:
      // time stamp counter and nominal core crystal clock information
      [[fallthrough]];
    case 0x16:
      // processor frequency information
      break;

    case 0x17:
      // system-on-chip vendor attribute enumeration. Not supported.
      a = b = c = d = 0;
      break;

    case 0x18:
      // deterministic address translation. Not supported.
      [[fallthrough]];
    case 0x19:
      // key locker. Not supported.
      [[fallthrough]];
    case 0x1a:
      // native model enumeration. Not supported.
      [[fallthrough]];
    case 0x1b:
      // pconfig. Not supported.
      [[fallthrough]];
    case 0x1c:
      // last branch records information. Not supported.
      [[fallthrough]];
    case 0x1d:
      // tile information main. Not supported.
      [[fallthrough]];
    case 0x1e:
      // TMUL information. Not supported.
      a = b = c = d = 0;
      break;

    case 0x8000'0000:
      {
        a = Cpuid_max_ext_info_leaf;
        b = c = d = 0; // reserved
        break;
      }

    case 0x8000'0001:
      {
        // a contains extended processor signature and feature bits
        b = 0; // reserved
        cpuid_reg_apply(&c, Cpuid_8000_0001_ecx_supported);
        cpuid_reg_apply(&d, Cpuid_8000_0001_edx_supported);
        break;
      }

    // processor brand string
    case 0x8000'0002:
      [[fallthrough]];
    case 0x8000'0003:
      [[fallthrough]];
    case 0x8000'0004:
      [[fallthrough]];


    // Intel: reserved
    // AMD: L1 cache information
    case 0x8000'0005:
      [[fallthrough]];

    // Intel: L2 cache information
    // AMD: TLB and L2/L3 cache information
    case 0x8000'0006:
      break;

    case 0x8000'0007:
      a = b = c = 0; // reserved
      cpuid_reg_apply(&d, Cpuid_8000_0007_edx_supported);
      break;

    case 0x8000'0008:
      {
        // a contains linear/physical address size
        cpuid_reg_apply(&b, Cpuid_8000_0008_ebx_supported);
        c = d = 0; // reserved
        break;
      }

    // reserved leaves
    case 0x8:
      [[fallthrough]];
    case 0xc:
      [[fallthrough]];
    case 0xe:
      [[fallthrough]];
    case 0x11:
      [[fallthrough]];
    case 0x13:
      if (a || b || c || d)
        warn().printf("Unexpected feature in reserved CPUID leaf "
                      "(eax = 0x%llx,exc = 0x%llx) a=0x%x b=0x%x c=0x%x d=0x%x\n",
                      rax, rcx, a, b, c, d);
      a = b = c = d = 0;
      break;

      // For future reference:
      //    case 0x8000001f:
      //      {
      //        // Memory encryption not supported.
      //        // https://docs.kernel.org/arch/x86/amd-memory-encryption.html
      //        a &= ~(Amd_sme_bit | Amd_sev_bit);
      //        break;
      //      }
    default:
      {
        warn().printf("Unexpected CPUID leaf eax = 0x%llx, ecx = 0x%llx\n",
                      rax, rcx);
        a = b = c = d = 0;
      }
    }

  if (0)
    trace().printf("[%3u] CPUID as modified: a: 0x%x, b: 0x%x, c: 0x%x, d: 0x%x\n",
                   id, a, b, c, d);

  return set_regs(a, b, c, d);
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
      [[fallthrough]];
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
  for (auto &dev : _timer_devices[vcpu_id])
    dev->ready();

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
