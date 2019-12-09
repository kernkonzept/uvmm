/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/sys/types.h>
#include <l4/util/rdtsc.h>

#include "debug.h"
#include "mem_types.h"
#include "msr_device.h"
#include "vm_memmap.h"
#include "ds_mmio_mapper.h"

namespace Vdev {

class Kvm_clock : public Vdev::Timer, public Vmm::Msr_device, public Device
{
  struct Wall_clock
  {
    l4_uint32_t version;
    l4_uint32_t sec;
    l4_uint32_t nsec;
  };
  static_assert(sizeof(Wall_clock) == 3 * 4,
                "KVM Wall_clock struct is compact.");

  struct Vcpu_time_info {
    l4_uint32_t   version;
    l4_uint32_t   pad0;
    l4_uint64_t   tsc_timestamp;
    l4_uint64_t   system_time;
    l4_uint32_t   tsc_to_system_mul;
    l4_int8_t     tsc_shift;
    l4_uint8_t    flags;
    l4_uint8_t    pad[2];
  } __attribute__((__packed__));

public:
  Kvm_clock(Vmm::Vm_mem const *memmap)
  : _boottime(l4_rdtsc()),
    _vcpu_time(nullptr),
    _vcpu_time_enable(false),
    _memmap(memmap)
  {
    l4_calibrate_tsc(l4re_kip());
  }

  bool read_msr(unsigned, l4_uint64_t *, unsigned) const override
  {
    // Nothing to read, above structures are memory mapped in the guest.
    return false;
  }

  bool write_msr(unsigned msr, l4_uint64_t addr, unsigned) override
  {
    switch (msr)
    {
      case 0x4b564d00: // MSR_KVM_WALL_CLOCK_NEW
        {
          trace().printf("KVMclock: write to msr 0x4b564d00 0x%llx\n", addr);

          // address must be 4-byte aligned
          auto gaddr = Vmm::Guest_addr(addr & (-1UL << 2));
          set_wall_clock(static_cast<Wall_clock *>(host_addr(gaddr)));
          break;
        }

      case 0x4b564d01: // MSR_KVM_SYSTEM_TIME_NEW
        {
          trace().printf("KVMclock: write to msr 0x4b564d01 0x%llx\n", addr);

          _vcpu_time_enable = addr & 1;

          // address must be 4-byte aligned
          auto gaddr = Vmm::Guest_addr(addr & (-1UL << 2));
          setup_vcpu_time(static_cast<Vcpu_time_info *>(host_addr(gaddr)));
          break;
        }

      // NOTE: below functions are disabled via CPUID leave 0x4000'0001 and
      // shouldn't be invoked by a guest.
      case 0x4b564d02: // MSR_KVM_ASYNC_PF_EN
        printf("WARNING: KVM async pf not implemented.\n");
        break;

      case 0x4b564d03: // MSR_KVM_STEAL_TIME
        printf("WARNING: KVM steal time not implemented.\n");
        break;

      case 0x4b564d04: // MSR_KVM_EOI_EN
        printf("WARNING: KVM EIO not implemented.\n");
        break;

      default: return false;
    }

    return true;
  }

  void tick() override
  {
    if (_vcpu_time && _vcpu_time_enable)
      {
        auto now = l4_rdtsc();

        std::lock_guard<std::mutex> lock(_mutex);

        ++_vcpu_time->version;
        _vcpu_time->tsc_timestamp = now;
        _vcpu_time->system_time = l4_tsc_to_ns(now);
        ++_vcpu_time->version; // XXX make atomic barrier
      }
  }

private:
  void set_wall_clock(Wall_clock *cs) const
  {
    trace().printf("set wall clock address: %p \n", cs);

    cs->version = 1;
    l4_tsc_to_s_and_ns(_boottime, &(cs->sec), &(cs->nsec));
    cs->version = 0;
  }

  void setup_vcpu_time(Vcpu_time_info *vti)
  {
    trace().printf("set system time address: %p: enable: %i, scaler 0x%x\n",
                   vti, _vcpu_time_enable, l4_scaler_tsc_to_ns);

    vti->version = 0;
    vti->tsc_to_system_mul = l4_scaler_tsc_to_ns;
    vti->tsc_shift = 5;
    vti->flags = 0;
    _vcpu_time = vti;
  }

  void *host_addr(Vmm::Guest_addr addr) const
  {
    Vmm::Vm_mem::const_iterator f = _memmap->find(Vmm::Region(addr));
    if (f == _memmap->end())
      {
        Dbg().printf("Fail: 0x%lx memory not found.\n", addr.get());
        L4Re::chksys(-L4_EINVAL,
                     "Guest passes a valid RAM address.");
      }

    if (f->first.type != Vmm::Region_type::Ram)
      {
        Dbg().printf("Fail: 0x%lx region has invalid type %d.\n", addr.get(),
                     static_cast<int>(f->first.type));
        L4Re::chksys(-L4_EINVAL,
                     "Guest passes an address, that is backed by RAM.");
      }

    Ds_handler const *ds = dynamic_cast<Ds_handler *>(f->second.get());
    if (!ds)
      L4Re::chksys(-L4_EINVAL,
                   "Dataspace handler for guest RAM registered\n");

    return reinterpret_cast<void *>(
      (ds->local_start() + (addr.get() - f->first.start)).get());
  }

  static Dbg trace() { return Dbg(Dbg::Dev, Dbg::Warn, "KVMclock"); }

  l4_cpu_time_t _boottime;
  Vcpu_time_info *_vcpu_time;
  bool _vcpu_time_enable;
  Vmm::Vm_mem const *_memmap;
  std::mutex _mutex;
};

} // namespace
