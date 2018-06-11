/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/static_container>
#include <l4/vbus/vbus>
#include <l4/l4virtio/l4virtio>

#include <map>

#include "cpu_dev_array.h"
#include "generic_guest.h"
#include "io_device.h"
#include "mem_access.h"
#include "timer.h"
#include "vcpu_ptr.h"
#include "virt_lapic.h"
#include "vmprint.h"
#include "zeropage.h"
#include "pt_walker.h"

namespace Vmm {

class Guest : public Generic_guest
{
public:
  enum { Default_rambase = 0, Boot_offset = 0 };

  Guest()
  : _ptw(Pt_walker(&_memmap)),
    _apics(Vdev::make_device<Gic::Lapic_array>())
  {
    add_mmio_device(_apics->mmio_region(), _apics);
  }

  static Guest *create_instance();

  void setup_device_tree(Vdev::Device_tree) {}

  void show_state_interrupts(FILE *, Vcpu_ptr) {}

  void register_io_device(Region const &region,
                          cxx::Ref_ptr<Io_device> const &dev);

  void register_timer_device(cxx::Ref_ptr<Vdev::Timer> const &dev)
  {
    _clock.add_timer(dev);
  }

  L4virtio::Ptr<void> load_linux_kernel(Ram_ds *ram, char const *kernel,
                                        l4_addr_t *entry);

  void prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry, Ram_ds *ram,
                         char const *kernel, char const *cmd_line,
                         l4_addr_t dt_boot_addr);

  void run(cxx::Ref_ptr<Cpu_dev_array> const &cpus) L4_NORETURN;

  void handle_entry(Vcpu_ptr vcpu);

  Gic::Virt_lapic *lapic(Vcpu_ptr vcpu)
  { return _apics->get(vcpu.get_vcpu_id()).get(); }

  cxx::Ref_ptr<Gic::Lapic_array> apic_array() { return _apics; }

  int handle_cpuid(l4_vcpu_regs_t *regs);
  int handle_vm_call(l4_vcpu_regs_t *regs);
  int handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                       l4_vcpu_regs_t *regs);

private:
  // guest physical address
  enum : unsigned { Linux_kernel_start_addr = 0x100000 };

  void run_vmx(cxx::Ref_ptr<Cpu_dev> const &cpu_dev) L4_NORETURN;

  int handle_exit_vmx(Vcpu_ptr vcpu);

  typedef std::map<Region, cxx::Ref_ptr<Io_device>> Io_mem;
  Io_mem _iomap;

  // devices
  Vdev::Clock_source _clock;
  Guest_print_buffer _hypcall_print;
  Pt_walker _ptw;
  cxx::Ref_ptr<Gic::Lapic_array> _apics;
};

} // namespace Vmm
