/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
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
#include "event_recorder.h"
#include "pm_device_if.h"

namespace Vmm {

class Guest : public Generic_guest
{
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

    // Do this once for all TSC-based timers used in uvmm.
    l4_calibrate_tsc(l4re_kip());
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
    Vdev::Pm_device_registry::suspend_devices();

    if (!_pm->suspend())
      {
        warn().printf("System suspend not possible. Waking up immediately.\n");
        Vdev::Pm_device_registry::resume_devices();
        return;
      }

    auto vcpu = _cpus->cpu(0)->vcpu();
    /* Go to sleep */
    vcpu.wait_for_ipc(l4_utcb(), L4_IPC_NEVER);

    /* Back alive */
    _pm->resume();
    Vdev::Pm_device_registry::resume_devices();

    vcpu.vm_state()->init_state();
    vcpu.vm_state()->setup_real_mode(wake_vector);
    info().printf("Waking CPU %u on EIP 0x%lx\n", 0, wake_vector);
  }

  void sync_all_other_cores_off() const override;
  // returns the number of running cores
  unsigned cores_running() const;

  void handle_entry(Vcpu_ptr vcpu);

  Gic::Virt_lapic *lapic(Vcpu_ptr vcpu)
  { return _apics->get(vcpu.get_vcpu_id()).get(); }

  cxx::Ref_ptr<Gic::Lapic_array> apic_array() { return _apics; }
  cxx::Ref_ptr<Gic::Icr_handler> icr_handler() { return _icr_handler; }

  int handle_cpuid(Vcpu_ptr vcpu);
  int handle_vm_call(l4_vcpu_regs_t *regs);

  /**
   * Access IO port and load/store the value to RAX.
   *
   * In case the given IO port is not handled by any device on read, the value
   * of all ones is stored to RAX. Write errors are silently ignored.
   *
   * \param[in]     port      IO port to access.
   * \param[in]     is_in     True if this is the IN (read) access.
   * \param[in]     op_width  Width of the access (1/2/4 bytes).
   * \param[in,out] regs      Register file. The value read/written is
   *                          stored/loaded into RAX.
   *
   * \retval Jump_instr  Success, all errors are silently ignored.
   */
  int handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                       l4_vcpu_regs_t *regs);

  /**
   * Access IO port (core implementation).
   *
   * Core implementation of accessing an IO port. The method looks up the
   * device that handles the IO port and does the access.
   *
   * \param[in]     port      IO port to access.
   * \param[in]     is_in     True if this is the IN (read) access.
   * \param[in]     op_width  Width of the access (1/2/4 bytes).
   * \param[in,out] value     Value to read/write.
   *
   * \retval true   The IO access was successful.
   * \retval false  No device handles the given IO port.
   */
  bool handle_io_access_ptr(unsigned port, bool is_in,
                            Mem_access::Width op_width, l4_uint32_t *value);

  void run_vm(Vcpu_ptr vcpu) L4_NORETURN;

  Boot::Binary_type guest_type() const
  { return _guest_t; }

private:
  enum : unsigned
  {
    Max_phys_addr_bits_mask = 0xff,
  };

  struct Xsave_state_area
  {
    struct Size_off { l4_uint64_t size = 0, offset = 0; };

    enum
    {
      // Some indices are valid in xcr0, some is xss.
      x87 = 0,      // XCR0
      sse,          // XCR0
      avx,          // XCR0
      mpx1,         // XCR0
      mpx2,         // XCR0
      avx512_1,     // XCR0
      avx512_2,     // XCR0
      avx512_3,     // XCR0
      pts,          // XSS
      pkru,         // XCR0,
      pasid,        // XSS
      cetu,         // XSS
      cets,         // XSS
      hdc,          // XSS
      uintr,        // XSS
      lbr,          // XSS
      hwp,          // XSS
      tilecfg,      // XCR0
      tiledata,     // XCR0

      Num_fields = 31,
    };

    bool valid = false;
    // first two fields are legacy area, so always (size=0, offset=0);
    Size_off feat[Num_fields];
  };

  template<typename VMS>
  void run_vm_t(Vcpu_ptr vcpu, VMS *vm) L4_NORETURN;

  template <typename VMS>
  bool event_injection_t(Vcpu_ptr vcpu, VMS *vm);

  template <typename VMS>
  int handle_exit(Cpu_dev *cpu, VMS *vm);

  unsigned get_max_physical_address_bit() const
  {
    l4_umword_t ax, bx, cx, dx;

    // Check for highest extended CPUID leaf
    l4util_cpu_cpuid(0x80000000, &ax, &bx, &cx, &dx);

    if (ax >= 0x80000008)
      l4util_cpu_cpuid(0x80000008, &ax, &bx, &cx, &dx);
    else
      {
        // Check for highest basic CPUID leaf
        l4util_cpu_cpuid(0x00, &ax, &bx, &cx, &dx);

        if (ax >= 0x01)
          {
            l4util_cpu_cpuid(0x01, &ax, &bx, &cx, &dx);
            if (dx & (1UL << 6)) // PAE
              ax = 36;
            else
              ax = 32;
          }
        else
          ax = 32; // Minimum if leaf not supported
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

  Event_recorder *recorder(unsigned num)
  { return _event_recorders.recorder(num); }

  /**
   * Perform actions necessary when changing from one Cpu_dev state to another.
   *
   * \tparam VMS       SVM or VMX state type
   * \param current    Current CPU state
   * \param new_state  CPU state to transition into
   * \param lapic      local APIC of the current vCPU
   * \param vm         SVM or VMX state
   * \param cpu        current CPU device
   */
  template <typename VMS>
  bool state_transition_effects(Cpu_dev::Cpu_state const current,
                                Cpu_dev::Cpu_state const new_state,
                                Gic::Virt_lapic *lapic, VMS *vm, Cpu_dev *cpu);

  /**
   * Perform actions of the state the Cpu_dev just transitioned into.
   *
   * \tparam VMS      SVM or VMX state type
   * \param state     New CPU state after state transition
   * \param halt_req  true, if `state` is the halt state and events are pending
   * \param cpu       current CPU device
   * \param vm        SVM or VMX state
   */
  template <typename VMS>
  bool new_state_action(Cpu_dev::Cpu_state state, bool halt_req, Cpu_dev *cpu,
                        VMS *vm);

  void iomap_dump(Dbg::Verbosity l)
  {
    Dbg d(Dbg::Dev, l, "vmmap");
    if (d.is_active())
      {
        d.printf("IOport map:\n");
        std::lock_guard<std::mutex> lock(_iomap_lock);
        for (auto const &r : _iomap)
          d.printf(" [%4lx:%4lx]: %s\n", r.first.start, r.first.end,
                   r.second->dev_name());
      }
  }
  std::mutex _iomap_lock;
  Io_mem _iomap;

  std::vector<cxx::Ref_ptr<Msr_device>> _msr_devices;
  std::vector<cxx::Ref_ptr<Cpuid_device>> _cpuid_devices;

  // devices
  std::map<unsigned, Vdev::Clock_source> _clocks;
  Guest_print_buffer _hypcall_print;
  cxx::Ref_ptr<Pt_walker> _ptw;
  cxx::Ref_ptr<Gic::Lapic_array> _apics;
  cxx::Ref_ptr<Gic::Icr_handler> _icr_handler;
  cxx::Ref_ptr<Gic::Lapic_access_handler> _lapic_access_handler;
  Boot::Binary_type _guest_t;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
  Vmm::Event_recorder_array _event_recorders;
  Xsave_state_area _xsave_layout;
};

/**
 * Handler for MSR read/write to a specific vCPU with its corresponding
 * VM state.
 */
class Vcpu_msr_handler : public Msr_device
{
public:
  Vcpu_msr_handler(Cpu_dev_array *cpus,
                   Vmm::Event_recorders *ev_rec)
  : _cpus(cpus), _ev_rec(ev_rec)
  {};

  bool read_msr(unsigned msr, l4_uint64_t *value, unsigned vcpu_no) const override
  {
    return _cpus->vcpu(vcpu_no).vm_state()->read_msr(msr, value);
  }

  bool write_msr(unsigned msr, l4_uint64_t value, unsigned vcpu_no) override
  {
    return _cpus->vcpu(vcpu_no)
      .vm_state()
      ->write_msr(msr, value, _ev_rec->recorder(vcpu_no));
  }

private:
  Cpu_dev_array *_cpus;
  Event_recorders *_ev_rec;
};

/**
 * Handler for MSR access to all MTRR registeres.
 *
 * MTRR are architectural registers and do not differ between AMD and Intel.
 * MTRRs are core specific and must be kept in sync.
 * Since all writes are ignored and reads just show the static state, we do
 * no core specific handling for these registers.
 */
class Mtrr_msr_handler : public Msr_device
{
public:
  Mtrr_msr_handler() = default;

  bool read_msr(unsigned msr, l4_uint64_t *value, unsigned) const override
  {
    switch(msr)
      {
      case 0xfe:           // IA32_MTRRCAP, RO
        *value = 1U << 10; // WriteCombining support bit.
        break;
      case 0x2ff:          // IA32_MTRR_DEF_TYPE
        *value = 1U << 11; // E/MTRR enable bit
        break;

      // MTRRphysMask/Base[0-9]; only present if IA32_MTRRCAP[7:0] > 0
      case 0x200: case 0x201: case 0x202: case 0x203: case 0x204: case 0x205:
      case 0x206: case 0x207: case 0x208: case 0x209: case 0x20a: case 0x20b:
      case 0x20c: case 0x20d: case 0x20e: case 0x20f: case 0x210: case 0x211:
      case 0x212: case 0x213:
        *value = 0;
        break;

      case 0x250:  // MTRRfix64K_0000
          // fall-through
      case 0x258:  // MTRRfix16K
          // fall-through
      case 0x259:  // MTRRfix16K
          // fall-through
      // MTRRfix_4K_*
      case 0x268: case 0x269: case 0x26a: case 0x26b: case 0x26c: case 0x26d:
      case 0x26e: case 0x26f:
        *value = 0;
        break;

      default:
        return false;
      }

    return true;
  }

  bool write_msr(unsigned msr, l4_uint64_t, unsigned) override
  {
    switch(msr)
      {
      case 0x2ff: // MTRRdefType
        // We report no MTRRs in the MTRRdefType MSR. Thus we ignore writes here.
        // MTRRs might also be disabled temporarily by the guest.
        break;

      // Ignore all writes to MTRR registers, we flagged all of them as unsupported
      // MTRRphysMask/Base[0-9]; only present if MTRRcap[7:0] > 0
      case 0x200: case 0x201: case 0x202: case 0x203: case 0x204: case 0x205:
      case 0x206: case 0x207: case 0x208: case 0x209: case 0x20a: case 0x20b:
      case 0x20c: case 0x20d: case 0x20e: case 0x20f: case 0x210: case 0x211:
      case 0x212: case 0x213:
        break;

      case 0x250:  // MTRRfix64K_0000
          // fall-through
      case 0x258:  // MTRRfix16K
          // fall-through
      case 0x259:  // MTRRfix16K
          // fall-through
      // MTRRfix_4K_*
      case 0x268: case 0x269: case 0x26a: case 0x26b: case 0x26c: case 0x26d:
      case 0x26e: case 0x26f:
        break;

      default:
        return false;
      }

    return true;
  }
}; // class Mtrr_msr_handler

} // namespace Vmm
