/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2018-2022 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */
#pragma once

#include <l4/util/cpu.h>
#include <l4/vbus/vbus>
#include <l4/l4virtio/l4virtio>

#include <map>
#include <mutex>
#include <vector>

#include "cpu_dev_array.h"
#include "generic_guest.h"
#include "msr_device.h"
#include "cpuid_device.h"
#include "mem_access.h"
#include "timer.h"
#include "vcpu_ptr.h"
#include "virt_lapic.h"
#include "vmprint.h"
#include "zeropage.h"
#include "pt_walker.h"
#include "vm_ram.h"
#include "binary_loader.h"

namespace Vmm {

class Guest : public Generic_guest
{
  enum : unsigned { Max_cpus = Cpu_dev::Max_cpus };

public:
  enum { Default_rambase = 0, Boot_offset = 0 };

  enum { Has_io_space = true };
  using Io_mem = std::map<Io_region, cxx::Ref_ptr<Io_device>>;

  Guest()
  : _apics(Vdev::make_device<Gic::Lapic_array>()),
    _icr_handler(Vdev::make_device<Gic::Icr_handler>()),
    _lapic_access_handler(Vdev::make_device<Gic::Lapic_access_handler>(
      _apics, _icr_handler, get_max_physical_address_bit()))
  {
    add_mmio_device(_lapic_access_handler->mmio_region(),
                    _lapic_access_handler);
    register_msr_device(_lapic_access_handler);
  }

  static Guest *create_instance();
  static Guest *get_instance();

  void setup_device_tree(Vdev::Device_tree) {}

  void show_state_interrupts(FILE *, Vcpu_ptr) {}

  void register_io_device(cxx::Ref_ptr<Vmm::Io_device> const &dev,
                          Region_type type,
                          Vdev::Dt_node const &node, size_t index = 0);
  void add_io_device(Io_region const &region,
                     cxx::Ref_ptr<Io_device> const &dev);
  void del_io_device(Io_region const &region);

  bool register_framebuffer(l4_uint64_t addr, l4_uint64_t size,
                            const L4Re::Video::View::Info &info);

  /**
   * Return IO port map.
   *
   * Must only be used before the guest started to run or for debugging. Might
   * be manipulated concurrently from other vCPUs!
   */
  Io_mem const *iomap()
  { return &_iomap; }

  void register_msr_device(cxx::Ref_ptr<Msr_device> const &dev);

  /**
   * Register a CPUID-handling device in a list.
   *
   * \param dev   CPUID-handling device to register.
   */
  void register_cpuid_device(cxx::Ref_ptr<Cpuid_device> const &dev);

  /**
   * Register a device for a timer.
   *
   * Uniprocessor timer devices such as the legacy PIT are registered ommiting
   * the CPU numbers and run off the clock source for vCPU 0.
   *
   * Timers registered at run time (e.g. via KVM clock MSR) specify their
   * core's CPU IDs.
   *
   * \param dev      Timer device to register with a clock source.
   * \param vcpu_no  Virtual CPU that the timer should be registered for,
   *                 default 0.
   */
  void register_timer_device(cxx::Ref_ptr<Vdev::Timer> const &dev,
                             unsigned vcpu_no = 0)
  {
    assert(vcpu_no < Max_cpus);

    _clocks[vcpu_no].add_timer(dev);
  }

  l4_addr_t load_binary(Vm_ram *ram, char const *binary,
                        Ram_free_list *free_list);

  void prepare_platform(Vdev::Device_lookup *devs);

  void prepare_binary_run(Vdev::Device_lookup *devs, l4_addr_t entry,
                          char const *binary, char const *cmd_line,
                          l4_addr_t dt_boot_addr);

  void run(cxx::Ref_ptr<Cpu_dev_array> const &cpus);

  void suspend(l4_addr_t wake_vector)
  {
    if (!_pm->suspend())
      {
        warn().printf("System suspend not possible. Waking up immediately.\n");
        return;
      }

    /* Go to sleep */
    wait_for_ipc(l4_utcb(), L4_IPC_NEVER);
    /* Back alive */
    _pm->resume();

    auto vcpu = _cpus->cpu(0)->vcpu();
    vcpu.vm_state()->init_state();
    vcpu.vm_state()->setup_real_mode(wake_vector);
    vcpu->r.sp = 0;
    vcpu->r.ip = wake_vector;
    Dbg().printf("Starting CPU %u on EIP 0x%lx\n", 0, wake_vector);
  }

  void handle_entry(Vcpu_ptr vcpu);

  Gic::Virt_lapic *lapic(Vcpu_ptr vcpu)
  { return _apics->get(vcpu.get_vcpu_id()).get(); }

  cxx::Ref_ptr<Gic::Lapic_array> apic_array() { return _apics; }
  cxx::Ref_ptr<Gic::Icr_handler> icr_handler() { return _icr_handler; }

  int handle_cpuid(l4_vcpu_regs_t *regs);
  int handle_vm_call(l4_vcpu_regs_t *regs);
  int handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                       l4_vcpu_regs_t *regs);

  void run_vm(Vcpu_ptr vcpu) L4_NORETURN;

private:
  enum : unsigned
  {
    Max_phys_addr_bits_mask = 0xff,
  };

  template<typename VMS>
  void run_vm_t(Vcpu_ptr vcpu, VMS *vm) L4_NORETURN;

  template<typename VMS>
  int handle_exit(Vcpu_ptr vcpu, VMS *vm);

  unsigned get_max_physical_address_bit() const
  {
    l4_umword_t ax, bx, cx, dx;
    // check for highest CPUID leaf:
    l4util_cpu_cpuid(0, &ax, &bx, &cx, &dx);

    if (ax == 0x80000008)
      l4util_cpu_cpuid(0x80000008, &ax, &bx, &cx, &dx);
    else
      {
        l4util_cpu_cpuid(0x1, &ax, &bx, &cx, &dx);
        if (dx & (1UL << 6)) // PAE
          ax = 36;           // minimum if leaf not supported
        else
          ax = 32;
      }

    return ax & Max_phys_addr_bits_mask;
  }

  bool msr_devices_rwmsr(l4_vcpu_regs_t *regs, bool write, unsigned vcpu_no);
  /**
   * Attempt to handle the CPUID instruction by consecutively trying handlers
   * of the CPUID-handling devices registered in the _cpuid_devices list. The
   * list is traversed from the front to the back.
   */
  bool handle_cpuid_devices(l4_vcpu_regs_t const *regs, unsigned *a,
                            unsigned *b, unsigned *c, unsigned *d);

  std::mutex _iomap_lock;
  Io_mem _iomap;

  std::vector<cxx::Ref_ptr<Msr_device>> _msr_devices;
  std::vector<cxx::Ref_ptr<Cpuid_device>> _cpuid_devices;

  // devices
  Vdev::Clock_source _clocks[Max_cpus];
  Guest_print_buffer _hypcall_print;
  cxx::Ref_ptr<Pt_walker> _ptw;
  cxx::Ref_ptr<Gic::Lapic_array> _apics;
  cxx::Ref_ptr<Gic::Icr_handler> _icr_handler;
  cxx::Ref_ptr<Gic::Lapic_access_handler> _lapic_access_handler;
  Boot::Binary_type _guest_t;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
};

/**
 * Handler for MSR read/write to a specific vCPU with its corresponding
 * VM state.
 */
class Vcpu_msr_handler : public Msr_device
{
public:
  Vcpu_msr_handler(Cpu_dev_array *cpus) : _cpus(cpus) {};

  bool read_msr(unsigned msr, l4_uint64_t *value, unsigned vcpu_no) const override
  {
    return _cpus->vcpu(vcpu_no).vm_state()->read_msr(msr, value);
  }

  bool write_msr(unsigned msr, l4_uint64_t value, unsigned vcpu_no) override
  {
    return _cpus->vcpu(vcpu_no).vm_state()->write_msr(msr, value);
  }

private:
  Cpu_dev_array *_cpus;
};

} // namespace Vmm
