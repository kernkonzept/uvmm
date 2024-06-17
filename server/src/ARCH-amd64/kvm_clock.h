/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2020, 2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *            Benjamin Lamowski <benjamin.lamowski@kernkonzept.com>
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/util/rdtsc.h>
#include <l4/cxx/ref_ptr>
#include <vector>

#include "debug.h"
#include "mem_types.h"
#include "msr_device.h"
#include "cpuid_device.h"
#include "vm_ram.h"
#include "ds_mmio_mapper.h"
#include "cpu_dev.h"
#include "guest.h"

namespace Vdev {

struct Vcpu_time_info
{
  l4_uint32_t   version;
  l4_uint32_t   pad0;
  l4_uint64_t   tsc_timestamp;
  l4_uint64_t   system_time;
  l4_uint32_t   tsc_to_system_mul;
  l4_int8_t     tsc_shift;
  // bit 0 is set, if all Vcpu_time_info instances show the same TSC value.
  l4_uint8_t    flags;
  l4_uint8_t    pad[2];
};
static_assert(sizeof(Vcpu_time_info) == 32,
              "Vcpu_time_info structure is compact.");

class Kvm_clock : public Vdev::Timer, public Device
{

public:
  Kvm_clock(Vcpu_time_info *vti, bool enable)
  {
    configure(vti, enable);
  }

  void configure(Vcpu_time_info *vti, bool enable)
  {
    _vcpu_time_enable = enable;
    vti->version = 0;
    vti->tsc_to_system_mul = l4_scaler_tsc_to_ns;
    vti->tsc_shift = 5;
    vti->flags = 0;
    _vcpu_time = vti;
  }

  void tick()
  {
    auto now = l4_rdtsc();

    cxx::write_now(&(_vcpu_time->version), _vcpu_time->version + 1);
    _vcpu_time->tsc_timestamp = now;
    _vcpu_time->system_time = l4_tsc_to_ns(now);
    cxx::write_now(&(_vcpu_time->version), _vcpu_time->version + 1);
  }

private:
  Vcpu_time_info *_vcpu_time;
  bool _vcpu_time_enable;
  std::mutex _mutex;
};

class Kvm_clock_ctrl : public Vmm::Msr_device,
                       public Vmm::Cpuid_device,
                       public Device
{
  struct Wall_clock
  {
    l4_uint32_t version;
    l4_uint32_t sec;
    l4_uint32_t nsec;
  };
  static_assert(sizeof(Wall_clock) == 3 * 4,
                "KVM Wall_clock struct is compact.");

  enum Kvm_msrs : unsigned
  {
    Msr_kvm_wall_clock_new = 0x4b564d00,
    Msr_kvm_system_time_new = 0x4b564d01,
    Msr_kvm_async_pf_en = 0x4b564d02,
    Msr_kvm_steal_time = 0x4b564d03,
    Msr_kvm_eoi_en = 0x4b564d04,
  };

public:
  Kvm_clock_ctrl(cxx::Ref_ptr<Vmm::Vm_ram> const &memmap,
                 Vmm::Guest *vmm)
  : _boottime(l4_rdtsc()),
    _memmap(memmap),
    _vmm(vmm)
  {}

  bool read_msr(unsigned, l4_uint64_t *, unsigned) const override
  {
    // Nothing to read, above structures are memory mapped in the guest.
    return false;
  }

  bool write_msr(unsigned msr, l4_uint64_t addr, unsigned core_no) override
  {
    switch (msr)
      {
      case Msr_kvm_wall_clock_new:
        {
          trace().printf("Msr_kvm_wall_clock_new with addr 0x%llx\n", addr);

          // address must be 4-byte aligned
          auto gaddr = Vmm::Guest_addr(addr & (-1UL << 2));
          set_wall_clock(static_cast<Wall_clock *>(host_addr(gaddr)));
          break;
        }

      case Msr_kvm_system_time_new:
        {
          trace().printf("Msr_kvm_system_time_new to addr 0x%llx\n", addr);

          bool enable = addr & 1;

          // address must be 4-byte aligned
          auto gaddr = Vmm::Guest_addr(addr & (-1UL << 2));
          setup_vcpu_time(static_cast<Vcpu_time_info *>(host_addr(gaddr)),
                          enable, core_no);
          break;
        }

      // NOTE: below functions are disabled via CPUID leaf 0x4000'0001 and
      // shouldn't be invoked by a guest.
      case Msr_kvm_async_pf_en:
        warn().printf("KVM async pf not implemented.\n");
        break;
      case Msr_kvm_steal_time:
        warn().printf("KVM steal time not implemented.\n");
        break;
      case Msr_kvm_eoi_en:
        warn().printf("KVM EIO not implemented.\n");
        break;
        // If the guest Linux is compiled with CONFIG_KVM and no-kvmclock is
        // set on the command line, Linux will try to write to these MSRs on
        // shutdown. We ignore that.
      case 0x11:
      case 0x12:
        return true;
      default:
        return false;
      }

    return true;
  }

  bool handle_cpuid(l4_vcpu_regs_t const *regs, unsigned *a, unsigned *b,
                    unsigned *c, unsigned *d) const override
  {
    enum Cpuid_kvm_constants
    {
      Kvm_feature_clocksource = 1UL,       // clock at msr 0x11 & 0x12
      Kvm_feature_clocksource2 = 1UL << 3, // clock at msrs 0x4b564d00 & 01;
      // host communicates synchronized KVM clocks via Vcpu_time_info.flags[0]
      Kvm_feature_clocksource_stable_bit = 1UL << 24,
    };

    switch (regs->ax)
      {
        case 0x40000000:
          *a = 0x40000001; // max CPUID leaf in the 0x4000'0000 range.
          *b = 0x4b4d564b; // "KVMK"
          *c = 0x564b4d56; // "VMKV"
          *d = 0x4d;       // "M\0\0\0"
          return true;
        case 0x40000001:
          *a = Kvm_feature_clocksource2 | Kvm_feature_clocksource_stable_bit;
          *d = 0;
          *b = *c = 0;
          return true;
        default:
          return false;
      }
  }

private:
  void set_wall_clock(Wall_clock *cs) const
  {
    trace().printf("Set wall clock address: %p \n", cs);

    cxx::write_now(&(cs->version), 1U);
    l4_tsc_to_s_and_ns(_boottime, &(cs->sec), &(cs->nsec));
    cxx::write_now(&(cs->version), 0U);
  }

  void setup_vcpu_time(Vcpu_time_info *vti, bool enable, unsigned core_no)
  {
    trace().printf("set system time address: %p: enable: %i, scaler 0x%x\n",
                   vti, enable, l4_scaler_tsc_to_ns);

    if (core_no >= _clocks.size())
      _clocks.resize(core_no + 1);

    if (_clocks[core_no])
      _clocks[core_no]->configure(vti, enable);
    else
      {
        auto clock_dev = Vdev::make_device<Kvm_clock>(vti, enable);
        _clocks[core_no] = clock_dev;
        clock_dev->tick();
      }
  }

  void *host_addr(Vmm::Guest_addr addr) const
  {
    return _memmap->guest2host<void *>(addr);
  }

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Trace, "KVMclock"); }
  static Dbg warn() { return Dbg(Dbg::Dev, Dbg::Warn, "KVMclock"); }

  l4_cpu_time_t _boottime;
  std::vector<cxx::Ref_ptr<Kvm_clock>> _clocks;
  cxx::Ref_ptr<Vmm::Vm_ram> _memmap;
  Vmm::Guest *_vmm;
};

} // namespace
