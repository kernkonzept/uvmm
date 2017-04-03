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
  : _ptw(Pt_walker(&_memmap))
  {}

  static Guest *create_instance();

  void setup_device_tree(Vdev::Device_tree) {}

  void show_state_interrupts(FILE *, Vcpu_ptr) {}

  void register_io_device(cxx::Ref_ptr<Io_device> const &dev, l4_addr_t start,
                          l4_size_t sz);

  void register_timer_device(cxx::Ref_ptr<Vdev::Timer> const &dev)
  {
    _clock.add_timer(dev);
  }

  L4virtio::Ptr<void> load_linux_kernel(Ram_ds *ram, char const *kernel,
                                        l4_addr_t *entry);

  void prepare_linux_run(Vcpu_ptr vcpu, l4_addr_t entry, Ram_ds *ram,
                         char const *kernel, char const *cmd_line,
                         l4_addr_t dt_boot_addr);

  void run(cxx::Ref_ptr<Cpu_dev_array> const &cpus);

  void handle_entry(Vcpu_ptr vcpu);

  void set_apic_array(cxx::Ref_ptr<Gic::Apic_array> arr)
  { _apics = arr; }

  void add_lapic(cxx::Ref_ptr<Gic::Virt_lapic> const &lapic, unsigned id)
  { assert(_apics); _apics->add(id, lapic); }

  Gic::Virt_lapic *current_lapic(Vmm::Vcpu_ptr vcpu)
  { assert(_apics); return _apics->lapic(vcpu.get_vcpu_id()); }

  int handle_cpuid(l4_vcpu_regs_t *regs);
  int handle_vm_call(l4_vcpu_regs_t *regs);
  int handle_io_access(unsigned port, bool is_in, Mem_access::Width op_width,
                       l4_vcpu_regs_t *regs);

private:
  // guest physical address
  enum : unsigned { Linux_kernel_start_addr = 0x100000 };

  void run_vmx(cxx::Ref_ptr<Cpu_dev> const &cpu_dev);

  int handle_exit_vmx(Vcpu_ptr vcpu);

  typedef std::map<Region, cxx::Ref_ptr<Io_device>> Io_mem;
  Io_mem _iomap;

  // devices
  Vdev::Clock_source _clock;
  Guest_print_buffer _hypcall_print;
  Pt_walker _ptw;
  cxx::Ref_ptr<Gic::Apic_array> _apics;
};

} // namespace Vmm
