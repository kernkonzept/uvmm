/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>
#include <l4/util/rdtsc.h>

#include <climits>

#include "debug.h"
#include "virt_lapic.h"
#include "mad.h"
#include "guest.h"


namespace Gic {

using L4Re::chkcap;
using L4Re::chksys;

Virt_lapic::Virt_lapic(unsigned id, l4_addr_t baseaddr)
: _lapic_irq(chkcap(L4Re::Util::make_unique_cap<L4::Irq>())),
  _lapic_memory_address(baseaddr),
  _lapic_x2_id(id),
  _lapic_version(Lapic_version),
  _x2apic_enabled(false)
{
  Dbg().printf("Virt_lapic ctor\n");

  chksys(L4Re::Env::env()->factory()->create(_lapic_irq.get()),
         "Create APIC IRQ.");
}

void
Virt_lapic::init_device(Vdev::Device_lookup const *devs, Vdev::Dt_node const &)
{
  devs->vmm()->add_lapic(cxx::Ref_ptr<Virt_lapic>(this), _lapic_x2_id);
}

void
Virt_lapic::set(unsigned irq)
{
  irq_trigger(irq);
}

void
Virt_lapic::clear(unsigned irq)
{
  if (_irq_queued[irq])
    --_irq_queued[irq];
}

void
Virt_lapic::bind_irq_source(unsigned irq,
                            cxx::Ref_ptr<Irq_source> const &src)
{
  assert (irq < 256); // sources array length
  if(_sources[irq])
    throw L4::Runtime_error(-L4_EEXIST);

  _sources[irq] = src;
}

cxx::Ref_ptr<Irq_source>
Virt_lapic::get_irq_source(unsigned irq) const
{
  assert (irq < 256); // sources array length
  return _sources[irq];
}

int
Virt_lapic::dt_get_num_interrupts(Vdev::Dt_node const &node)
{
  int size;
  auto ret = node.get_prop<fdt32_t>("interrupts", &size);
  Dbg().printf("VIRT_LAPIC: num interrupts: %i\n", size);
  if (!ret || size == 0)
    return 0;
  return 1;
}

unsigned
Virt_lapic::dt_get_interrupt(Vdev::Dt_node const &, int)
{
  return 1;
}

void
Virt_lapic::tick()
{
  enum
  {
    TSC_deadline = 0x40000,
    Mask = 0x10000,
    Periodic_deadline = 0x20000,
    Timer_vector_mask = 0xff,
    Int_pending_bit = 0x1 << 12,
  };

  std::lock_guard<std::mutex> lock(_tmr_mutex);

  if (0)
    {
      static unsigned cnt = 0;
      if ((++cnt % 100) == 0)
        Dbg()
          .printf("VAPIC: Tick TSC DL ? %s : %llx, now: %llx, timer reg: %x\n",
                  (_regs.timer & TSC_deadline) ? "yes" : "no", _tsc_deadline,
                  l4_rdtsc(), _regs.timer);
    }

  if (_regs.timer & TSC_deadline)
    {
      if (_tsc_deadline > 0 && _tsc_deadline <= l4_rdtsc())
        {
          if (!(_regs.timer & Mask))
              irq_trigger(_regs.timer & Timer_vector_mask);

          _tsc_deadline = 0;
        }
    }
  else if (_regs.tmr_cur > 0)
    {
      if (--_regs.tmr_cur == 0)
        {
          if (!(_regs.timer & Mask))
            irq_trigger(_regs.timer & Timer_vector_mask);

          if (_regs.timer & Periodic_deadline)
            _regs.tmr_cur = _regs.tmr_init;
        }
    }
}

/// Update the pending interrupt array and send an interrupt to the vCPU.
void
Virt_lapic::irq_trigger(l4_uint32_t irq)
{
    {
      std::lock_guard<std::mutex> lock(_int_mutex);
      if (_irq_queued[irq] < UINT_MAX)
        ++_irq_queued[irq];
    }

  _lapic_irq->trigger();
}

int
Virt_lapic::next_pending_irq()
{
  std::lock_guard<std::mutex> lock(_int_mutex);

  for (int i = 0; i < 256; ++i)
      if (_irq_queued[i] > 0)
        {
          --_irq_queued[i];
          return i;
        }

  return -1;
}

void
Virt_lapic::wait_for_irq()
{
    {
      std::lock_guard<std::mutex> lock(_int_mutex);

      for (int i = 0; i < 256; ++i)
        if (_irq_queued[i] > 0)
          return;

    }

  irq_clear();
}

bool
Virt_lapic::read_msr(unsigned msr, l4_uint64_t *value)
{
  switch (msr)
    {
    case 0x1b: // APIC base
      // 1UL << 11 = EN xAPIC global en/disable
      // 1UL << 8 = processor is BSP
      *value =
        (_lapic_memory_address & 0xffff00000) | (1UL << 11) | (1UL << 8);

      if (_x2apic_enabled)
        // 1UL << 10 = EXTD - Enable x2APIC mode
        *value |= 1UL << 10;
      break;
    case 0x6e0: *value = _tsc_deadline; break;
    case 0x802:
      *value = _x2apic_enabled
                 ? _lapic_x2_id
                 : (_lapic_x2_id << Xapic_mode_local_apic_id_shift);
      break;
    case 0x803: *value = _lapic_version; break;
    case 0x808: *value = _regs.tpr; break;
    case 0x80a: *value = _regs.ppr; break;
    case 0x80d: *value = _regs.ldr; break;
    case 0x80f: *value = _regs.svr; break;
    case 0x810:
    case 0x811:
    case 0x812:
    case 0x813:
    case 0x814:
    case 0x815:
    case 0x816:
    case 0x817: *value = _regs.isr[msr - 0x810]; break;
    case 0x818:
    case 0x819:
    case 0x81a:
    case 0x81b:
    case 0x81c:
    case 0x81d:
    case 0x81e:
    case 0x81f: *value = _regs.tmr[msr - 0x818]; break;
    case 0x820:
    case 0x821:
    case 0x822:
    case 0x823:
    case 0x824:
    case 0x825:
    case 0x826:
    case 0x827: *value = _regs.irr[msr - 0x820]; break;
    case 0x828: *value = _regs.esr; break;
    case 0x82f: *value = _regs.cmci; break;
    case 0x830: *value = _regs.icr; break;
    case 0x832: *value = _regs.timer; break;
    case 0x833: *value = _regs.therm; break;
    case 0x834: *value = _regs.perf; break;
    case 0x835: *value = _regs.lint[0]; break;
    case 0x836: *value = _regs.lint[1]; break;
    case 0x837: *value = _regs.err; break;
    case 0x838: *value = _regs.tmr_init; break;
    case 0x839: *value = _regs.tmr_cur; break;
    case 0x83e: *value = _regs.tmr_div; break;
    default: return false;
    }

  if (0)
    Dbg().printf("ReadAPIC MSR 0x%x. Result: 0x%x\n", (unsigned)msr,
                 (unsigned)*value);
  return true;
}

bool
Virt_lapic::write_msr(unsigned msr, l4_uint64_t value)
{
  switch(msr)
    {
    case 0x1b: // APIC base
      // 1UL << 10 = EXTD - Enable x2APIC mode
      _x2apic_enabled = value & (1UL << 10);
      if (_x2apic_enabled)
        Dbg().printf("------ x2APIC enabled\n");
      break;
    case 0x6e0:
      {
        std::lock_guard<std::mutex> lock(_tmr_mutex);
        _tsc_deadline = value;

        if (0)
          Dbg()
            .printf("New TSC dealine: 0x%llx (now: 0x%llx) timer status: %x\n",
                    value, l4_rdtsc(), _regs.timer);
        break;
      }
    case 0x803: _lapic_version = value; break;
    case 0x808: _regs.tpr = value; break;
    case 0x80f: _regs.svr = value; break;
    case 0x80b: // x2APIC EOI
                if(value != 0)
                  {
                    Dbg().printf("WARNING: write to EOI not zero, 0x%llx\n", value);
                    return false;
                  }
                break;
    case 0x828: _regs.esr = 0; break;
    case 0x82f: _regs.cmci = value; break;
    case 0x830: _regs.icr = value; break;
    case 0x832: _regs.timer = value; break;
    case 0x833: _regs.therm = value; break;
    case 0x834: _regs.perf = value; break;
    case 0x835: _regs.lint[0] = value; break;
    case 0x836: _regs.lint[1] = value; break;
    case 0x837: _regs.err = value; break;
    case 0x838:
      _regs.tmr_init = value;
      _regs.tmr_cur = value;
      break;
    case 0x83e: _regs.tmr_div = value; break;
    case 0x83f:
      Dbg().printf("TODO: self IPI\n");
      break;
    default:
      return false;
    }

  if (0 && msr != 0x80b)
    Dbg().printf("WARNING: APIC write to 0x%x: 0x%llx\n", msr, value);

  return true;
}

} // namepace Gic

#include "device_factory.h"
#include "guest.h"

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup const *,
                                    Vdev::Dt_node const &node) override
  {
    Dbg().printf("Creating virt_lapic\n");

    l4_uint64_t base = 0;
    l4_uint64_t size = 0;
    int index = 0;
    node.get_reg_val(index, &base, &size);
    l4_uint64_t cpu_id = 0;
    node.parent_node().get_reg_val(0, &cpu_id, 0);

    Dbg().printf("Read base 0x%llx & size 0x%llx & cpuid 0x%llx from the DT\n",
                 base, size, cpu_id);

    auto dev = Vdev::make_device<Gic::Virt_lapic>(cpu_id, base);

    Dbg().printf("Addr of lapic0: %p\n", dev.get());

    return dev;
  }
}; // struct F

static F f;
static Vdev::Device_type t = {"virt-lapic", nullptr, &f};
} // namespace

namespace {

struct G : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup const *devs,
                                    Vdev::Dt_node const &node) override
  {
    auto dev = Vdev::make_device<Gic::Apic_array>();
    devs->vmm()->set_apic_array(dev);
    devs->vmm()->register_mmio_device(dev, node);

    return dev;
  }
};

static G g;
static Vdev::Device_type d = {"apic-dist", nullptr, &g};
} // namespace
