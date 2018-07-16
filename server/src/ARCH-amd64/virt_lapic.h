/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <mutex>
#include <tuple>

#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/util/unique_cap>
#include <l4/sys/vcpu.h>

#include "irq.h"
#include "timer.h"
#include "mem_access.h"
#include "vm_state.h"
#include "pt_walker.h"
#include "ram_ds.h"
#include "msi_distributor.h"

using L4Re::Rm;

namespace Gic {

class Virt_lapic : public Vdev::Timer, public Ic
{
 public:
   Virt_lapic(unsigned id, l4_addr_t baseaddr);

   void attach_cpu_thread(L4::Cap<L4::Thread> vthread)
   {
     L4Re::chksys(_lapic_irq->bind_thread(vthread, 0),
                  "Attaching local APIC IRQ to vCPU thread");
   }

   // IC interface
   void set(unsigned irq) override;
   void clear(unsigned irq) override;

   void bind_irq_source(unsigned, cxx::Ref_ptr<Irq_source> const &) override;
   cxx::Ref_ptr<Irq_source> get_irq_source(unsigned ) const override;

   int dt_get_num_interrupts(Vdev::Dt_node const &) override;
   unsigned dt_get_interrupt(Vdev::Dt_node const &, int ) override;

   // Timer interface
   void tick() override;

   // APIC soft Irq to force VCPU to handle IRQs
   void irq_trigger(l4_uint32_t irq);

   // vCPU expected interface
   int next_pending_irq();
   bool is_irq_pending();

   // X2APIC MSR interface
   bool read_msr(unsigned msr, l4_uint64_t *value);
   bool write_msr(unsigned msr, l4_uint64_t value);

   l4_addr_t apic_base() const { return _lapic_memory_address; }

 private:
   struct LAPIC_registers
   {
     l4_uint32_t tpr;
     l4_uint32_t ppr;
     l4_uint32_t ldr;
     l4_uint32_t svr;
     l4_uint32_t isr[8];
     l4_uint32_t tmr[8];
     l4_uint32_t irr[8];
     l4_uint32_t esr;
     l4_uint32_t cmci;
     l4_uint64_t icr;
     l4_uint32_t timer;
     l4_uint32_t therm;
     l4_uint32_t perf;
     l4_uint32_t lint[2];
     l4_uint32_t err;
     l4_uint32_t tmr_init;
     l4_uint32_t tmr_cur;
     l4_uint32_t tmr_div;
    };

   L4Re::Util::Unique_cap<L4::Irq> _lapic_irq; /// IRQ to notify VCPU
   l4_addr_t _lapic_memory_address;
   unsigned _lapic_x2_id;
   unsigned _lapic_version;
   std::mutex _int_mutex;
   std::mutex _tmr_mutex;
   LAPIC_registers _regs;
   l4_uint64_t _tsc_deadline;
   bool _x2apic_enabled;
   unsigned _irq_queued[256];
   cxx::Ref_ptr<Irq_source> _sources[256];

   enum XAPIC_consts : unsigned
   {
     Xapic_mode_local_apic_id_shift = 24,
     Extended_apic_enable_bit = 1UL << 10,
     Lapic_version = 0x60010, /// 10 = integrated APIC, 6 = max LVT entries - 1
   };
}; // class Virt_lapic


#include "mmio_device.h"

class Lapic_array : public Vmm::Mmio_device_t<Lapic_array>, public Vdev::Device
{
  enum
  {
    // XXX sync with Max_cpus
    Max_cores = 1,
    X2apic_msr_base = 0x800,
    Lapic_mem_addr = 0xfee00000,
    Lapic_mem_size = 0x1000,
  };
  cxx::Ref_ptr<Virt_lapic> _lapics[Max_cores];

  unsigned reg2msr(unsigned reg) { return (reg >> 4) | X2apic_msr_base; }

public:
  Region mmio_region() const
  { return Region::ss(Lapic_mem_addr, Lapic_mem_size); }

  cxx::Ref_ptr<Virt_lapic> get(unsigned core_no)
  {
    assert(core_no < Max_cores);
    return _lapics[core_no];
  }

  void register_core(unsigned core_no)
  {
    if (_lapics[core_no])
      {
        Dbg().printf("Local APIC for core %u already registered\n", core_no);
        return;
      }

    _lapics[core_no] = Vdev::make_device<Virt_lapic>(core_no, Lapic_mem_addr);
  }

  // Mmio device if
  l4_umword_t read(unsigned reg, char, unsigned cpu_id)
  {
    l4_uint64_t val = -1;
    if (cpu_id < Max_cores)
        _lapics[cpu_id]->read_msr(reg2msr(reg), &val);

    return val;
  }

  void write(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
  {
    if (cpu_id < Max_cores)
      _lapics[cpu_id]->write_msr(reg2msr(reg), value);
  }
}; // class Lapic_array


/**
 * IO-APIC representation for IRQ/MSI routing. WIP!
 */
class Io_apic : public Ic, public Msi_distributor
{
public:
  Io_apic(cxx::Ref_ptr<Lapic_array> apics) : _apics(apics) {}

  // IC interface
  void set(unsigned irq) override
  { _apics->get(0)->set(irq); }

  void clear(unsigned irq) override
  { _apics->get(0)->clear(irq); }

  void bind_irq_source(unsigned irq, cxx::Ref_ptr<Irq_source> const &src) override
  { _apics->get(0)->bind_irq_source(irq, src); }

  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned irq) const override
  { return _apics->get(0)->get_irq_source(irq); }

  int dt_get_num_interrupts(Vdev::Dt_node const &node) override
  {
    int size;
    auto ret = node.get_prop<fdt32_t>("interrupts", &size);
    Dbg().printf("VIRT_LAPIC: num interrupts: %i\n", size);
    if (!ret || size == 0)
      return 0;
    return 1;
  }

  unsigned dt_get_interrupt(Vdev::Dt_node const &, int) override
  { return 1; }

  // Msi_distributor interface
  void send(Vdev::Msi_msg message) const override
  {
    // TODO implement MSI-X parsing such that malconfigured MSIs are dropped.
    _apics->get(0)->set(message.data & 0xff);
  }

private:
  cxx::Ref_ptr<Lapic_array> _apics;
}; // class Io_apic

} // namespace Gic
