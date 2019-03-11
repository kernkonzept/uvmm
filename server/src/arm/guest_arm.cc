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

static cxx::unique_ptr<Vmm::Guest> guest;

__thread unsigned vmm_current_cpu_id;

typedef void (*Entry)(Vmm::Vcpu_ptr vcpu);

namespace Vmm {

Guest::Guest()
: _gic(Vdev::make_device<Gic::Dist>(16, Vmm::Cpu_dev::Max_cpus))
{}

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

static Dt_node
get_psci_node(Device_tree const &dt)
{
  char const *compats[] = { "arm,psci", "arm,psci-0.2", "arm,psci-1.0" };

  for (auto compat : compats)
    {
      auto node = dt.first_compatible_node(compat);
      if (node.is_valid())
        return node;
    }
  return Dt_node();
}

void
Guest::setup_device_tree(Vdev::Device_tree dt)
{
  Dt_node parent;
  Dt_node node = get_psci_node(dt);

  if (node.is_valid())
    {
      parent = node.parent_node();
      if (node.del_node() < 0)
        {
          Err().printf("Failed to delete %s, unable to set psci methods\n",
                       node.get_name());
          return;
        }
    }
  else
    parent = dt.first_node();

  node = parent.add_subnode("psci");
  if (!node.is_valid())
    return;

  node.setprop_string("compatible", "arm,psci-0.2");
  node.setprop_string("method", "hvc");
}

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

  _cpus = cpus;
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

Cpu_dev *
Guest::lookup_cpu(l4_uint32_t hwid) const
{
  for (auto const &cpu : *_cpus.get())
    if (cpu && cpu->matches(hwid))
      return cpu.get();

  return nullptr;
}

bool
Guest::cpus_off() const
{
  bool first = true;
  for (auto const &cpu : *_cpus.get())
    {
      // ignore boot cpu
      if (first)
        {
          first = false;
          continue;
        }

      if (cpu && cpu->online())
          return false;
    }

  return true;
}

Cpu_dev *
Guest::current_cpu() const
{ return _cpus->cpu(vmm_current_cpu_id).get(); }

bool
Guest::handle_psci_call(Vcpu_ptr vcpu)
{
  enum Psci_error_codes
  {
    Success            = 0,
    Not_supported      = -1,
    Invalid_parameters = -2,
    Denied             = -3,
    Already_on         = -4,
    On_pending         = -5,
    Internal_failure   = -6,
    Not_present        = -7,
    Disabled           = -8,
    Invalid_address    = -9,
  };

  enum Psci_functions
  {
    Psci_version          = 0,
    Cpu_suspend           = 1,
    Cpu_off               = 2,
    Cpu_on                = 3,
    Affinity_info         = 4,
    Migrate               = 5,
    Migrate_info_type     = 6,
    Migrate_info_up_cpu   = 7,
    System_off            = 8,
    System_reset          = 9,
    Psci_features         = 10,
    Cpu_freeze            = 11,
    Cpu_default_suspend   = 12,
    Node_hw_state         = 13,
    System_suspend        = 14,
    Psci_set_suspend_mode = 15,
    Psci_stat_residency   = 16,
    Psci_stat_count       = 17,
  };

  enum Psci_migrate_info
  {
    Tos_up_mig_cap     = 0,
    Tos_not_up_mig_cap = 1,
    Tos_not_present_mp = 2,
  };

  enum Psci_affinity_info
  {
    Aff_info_on         = 0,
    Aff_info_off        = 1,
    Aff_info_on_pending = 2,
  };

  // Check this is a supported PSCI function call id.
  if (!is_psci_func_id(vcpu->r.r[0]))
      return false;

  l4_uint8_t func = vcpu->r.r[0] & 0x1f;
  switch (func)
    {
    case Psci_version:
      vcpu->r.r[0] = 0x00010000; // v1.0
      break;

    case Cpu_suspend:
      {
        l4_addr_t power_state  = vcpu->r.r[1];
        l4_addr_t entry_gpa    = vcpu->r.r[2];
        l4_umword_t context_id = vcpu->r.r[3];

        wait_for_timer_or_irq(vcpu);

        if (power_state & (1 << 30))
          {
            memset(&vcpu->r, 0, sizeof(vcpu->r));
            prepare_vcpu_startup(vcpu, entry_gpa);
            vcpu->r.r[0]  = context_id;
            l4_vcpu_e_write_32(*vcpu, L4_VCPU_E_SCTLR,
                               l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR) & ~1U);
          }
        else
          vcpu->r.r[0] = Success;
      }
      break;

    case Cpu_off:
      {
        Cpu_dev *target = current_cpu();
        target->stop();
        // should never return
        vcpu->r.r[0] =  Internal_failure;
      }
      break;

    case Cpu_on:
      {
        unsigned long hwid = vcpu->r.r[1];
        Cpu_dev *target = lookup_cpu(hwid);

        if (target)
          {
            // XXX There is currently no way to detect error conditions like
            // INVALID_ADDRESS
            if (!target->online() && target->mark_on_pending())
              {
                l4_mword_t ip = vcpu->r.r[2];
                l4_mword_t context =  vcpu->r.r[3];
                target->vcpu()->r.r[0] = context;
                prepare_vcpu_startup(target->vcpu(), ip);
                if (target->start_vcpu())
                  vcpu->r.r[0] = Success;
                else
                  vcpu->r.r[0] = Internal_failure;
              }
            else
              vcpu->r.r[0] = target->online_state() == Cpu_dev::Cpu_state::On
                             ? Already_on : On_pending;
          }
        else
          vcpu->r.r[0] = Invalid_parameters;
      }
      break;

    case Affinity_info:
      {
        // parameters:
        // * target_affinity
        // * lowest affinity level
        l4_mword_t hwid = vcpu->r.r[1];
        l4_umword_t lvl = vcpu->r.r[2];

        // Default to invalid in case we do not find a matching CPU
        vcpu->r.r[0] = Invalid_parameters;

        // There are at most 3 affinity levels
        if (lvl > 3)
          break;

        for (auto const &cpu : *_cpus.get())
          if (cpu && cpu->matches(hwid, lvl))
            {
              if (cpu->online())
                {
                  vcpu->r.r[0] = Aff_info_on;
                  break;
                }
              vcpu->r.r[0] = Aff_info_off;
            }
      }
      break;

    case Migrate_info_type:
      vcpu->r.r[0] = Tos_not_present_mp;
      break;

    case System_off:
      _pm.shutdown();
      exit(0);

    case System_reset:
      _pm.shutdown(true);
      exit(102); // 0x66 is also used by our syscon config

    case Psci_features:
      {
        // Check this uses an allowed SMCCC bitness and is a valid PSCI
        // function id.
        if (   !is_smccc_bitness_allowed(vcpu->r.r[1])
            || !is_psci_func_id(vcpu->r.r[1]))
          {
            vcpu->r.r[0] = Not_supported;
            return true;
          }

        l4_uint8_t feat_func = vcpu->r.r[1] & 0x1f;
        switch (feat_func)
          {
          case Cpu_suspend:
            vcpu->r.r[0] = 1 << 1;
            break;
          case Psci_version:
          case Cpu_on:
          case Cpu_off:
          case Affinity_info:
          case Migrate_info_type:
          case System_off:
          case System_reset:
          case Psci_features:
          case System_suspend:
            vcpu->r.r[0] = Success;
            break;
          default:
            vcpu->r.r[0] = Not_supported;
            break;
          };
      }
      break;

    case System_suspend:
        {
          // Request has to be executed on CPU0 (requirement imposed by us) and
          // all other CPUs have to be off (specification requirement)
          if (vmm_current_cpu_id != 0 || !cpus_off())
            {
              vcpu->r.r[0] = Denied;
              break;
            }

          l4_addr_t entry_gpa = vcpu->r.r[1];
          l4_umword_t context_id = vcpu->r.r[2];

          /* Go to sleep */
          if (_pm.suspend())
            wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
          /* Back alive */
          _pm.resume();

          memset(&vcpu->r, 0, sizeof(vcpu->r));
          prepare_vcpu_startup(vcpu, entry_gpa);
          vcpu->r.r[0]  = context_id;
          l4_vcpu_e_write_32(*vcpu, L4_VCPU_E_SCTLR,
                             l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_SCTLR) & ~1U);
        }
      break;

    default:
      warn().printf("... Not supported PSCI function 0x%x called\n", (unsigned)func);
      vcpu->r.r[0] = Not_supported;
      break;
    };

  return true;
}

void
Guest::handle_smc_call(Vcpu_ptr vcpu)
{
  if (_smc_handler)
    _smc_handler->smc(vcpu);
  else
    Err().printf("No handler for SMC call: a0=%lx a1=%lx ip=%lx lr=%lx\n",
                 vcpu->r.r[0], vcpu->r.r[1], vcpu->r.ip, vcpu.get_lr());

  vcpu->r.ip += 4;
}

bool
Guest::handle_uvmm_call(Vcpu_ptr vcpu)
{
  enum Uvmm_functions
  {
    Print_char = 0,
  };

  if ((vcpu->r.r[0] & 0xbfffff00) != 0x86000000)
    return false;

  unsigned func = vcpu->r.r[0] & 0xff;
  switch (func)
    {
    case Print_char:
      {
        char c = vcpu->r.r[1];
        _hypcall_print.print_char(c);
      }
      break;

    default:
      warn().printf("... Unknown l4 function 0x%x called\n", func);
      break;
    };

  return true;
}

static void dispatch_vm_call(Vcpu_ptr vcpu)
{
  enum Hvc_functions
  {
    Psci = 0,
    Uvmm = 1,
  };

  enum Smc_error : l4_int64_t
  {
    Not_supported = -1
  };

  l4_mword_t imm = vcpu->r.err & 0xffff;

  switch (imm)
    {
    case Psci:
      {
        // Check if this is a 64 bit call on a 32 bit system. If so, reject.
        if (!guest->is_smccc_bitness_allowed(vcpu->r.r[0]))
          {
            vcpu->r.r[0] = Not_supported;
            return;
          }
        if (guest->handle_psci_call(vcpu))
          return;
        // If this wasn't a PSCI function return unsupported
        vcpu->r.r[0] = Not_supported;
      }
      break;
    case Uvmm:
      if (guest->handle_uvmm_call(vcpu))
        return;
      break;
    }

  Err().printf("Unknown HVC call: imm=%lx, a0=%lx a1=%lx ip=%lx lr=%lx\n",
               imm, vcpu->r.r[0], vcpu->r.r[1], vcpu->r.ip, vcpu.get_lr());
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
  [0x13] = guest_unknown_fault,
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
