/*
 * Copyright (C) 2017 Kernkonzept GmbH.
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

   // Device interface
   void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override;

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
   void irq_clear() const { _lapic_irq->receive(); };
   void irq_trigger(l4_uint32_t irq);

   // vCPU expected interface
   int next_pending_irq();
   void wait_for_irq();

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
     Lapic_version = 0x60010, /// 10 = integrated APIC, 6 = max LVT entries - 1
   };
}; // class Virt_lapic

#include "mmio_device.h"

class Apic_array : public Vmm::Mmio_device_t<Apic_array>, public Vdev::Device
{
  enum
  {
    Max_apics = 2,
    X2apic_msr_base = 0x800,
  };

  cxx::Ref_ptr<Virt_lapic> _lapics[Max_apics];

  unsigned reg2msr(unsigned reg) { return (reg >> 4) | X2apic_msr_base; }

public:
  Apic_array() {}

  // Device interface
  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override
  {}

  void add(unsigned id, cxx::Ref_ptr<Virt_lapic> lapic)
  {
    assert(id < Max_apics);
    assert(!_lapics[id]);
    _lapics[id] = lapic;
  }

  Virt_lapic *lapic(unsigned cpu_id)
  {
    assert(cpu_id < Max_apics);
    return _lapics[cpu_id].get();
  }

  cxx::Ref_ptr<Virt_lapic> lapic_ref(unsigned cpu_id)
  {
    assert(cpu_id < Max_apics);
    return _lapics[cpu_id];
  }

  // Mmio device if
  l4_umword_t read(unsigned reg, char, unsigned cpu_id)
  {
    l4_uint64_t val = -1;
    if (cpu_id < Max_apics)
        _lapics[cpu_id]->read_msr(reg2msr(reg), &val);

    return val;
  }

  void write(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
  {
    if (cpu_id < Max_apics)
      _lapics[cpu_id]->write_msr(reg2msr(reg), value);
  }
}; // class Apic_array

} // namespace Gic
