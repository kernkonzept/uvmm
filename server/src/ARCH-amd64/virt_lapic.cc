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

Virt_lapic::Virt_lapic(unsigned id)
: _lapic_irq(chkcap(L4Re::Util::make_unique_cap<L4::Irq>())),
  _lapic_x2_id(id),
  _lapic_version(Lapic_version),
  _last_ticks_tsc(0),
  _x2apic_enabled(false)
{
  trace().printf("Virt_lapic ctor; ID 0x%x\n", id);

  chksys(L4Re::Env::env()->factory()->create(_lapic_irq.get()),
         "Create APIC IRQ.");

  // Set reset values of the LAPIC registers
  memset(&_regs, 0, sizeof(_regs));
  _regs.dfr = -1U;
  _regs.cmci = _regs.therm = _regs.perf = 0x00010000;
  _regs.lint[0] = _regs.lint[1] = _regs.err = 0x00010000;
  _regs.svr = 0x000000ff;
}

void
Virt_lapic::set(unsigned irq)
{
  irq_trigger(irq);
}

void
Virt_lapic::set(Vdev::Msix::Data_register_format data)
{
  using namespace Vdev::Msix;

  irq_trigger(data.vector(),
              data.delivery_mode() == Dm_fixed
                || data.delivery_mode() == Dm_lowest_prio);
}

void
Virt_lapic::bind_eoi_handler(unsigned irq, Eoi_handler *handler)
{
  assert (irq < 256); // sources array length
  if(handler && _sources[irq])
    throw L4::Runtime_error(-L4_EEXIST);

  _sources[irq] = handler;
}

Eoi_handler *
Virt_lapic::get_eoi_handler(unsigned irq) const
{
  assert (irq < 256); // sources array length
  return _sources[irq];
}

int
Virt_lapic::dt_get_interrupt(fdt32_t const *, int, int *) const
{ return 1; }

void
Virt_lapic::tick()
{
  std::lock_guard<std::mutex> lock(_tmr_mutex);

  if (0 & !_timer.masked())
    {
      static unsigned cnt = 0;
      if ((++cnt % 100) == 0)
        Dbg()
          .printf("VAPIC: Tick TSC DL ? %s : %llx, now: %llx, _timer reg: %x\n",
                  _timer.tsc_deadline() ? "yes" : "no", _tsc_deadline,
                  l4_rdtsc(), _timer.raw);
    }

  if (_timer.tsc_deadline())
    {
      if (_tsc_deadline > 0 && _tsc_deadline <= l4_rdtsc())
        {
          if (_timer.masked())
            _timer.pending() = 1;
          else
            irq_trigger(_timer.vector());

          _tsc_deadline = 0;
        }
    }
  else if (_regs.tmr_cur > 0)
    {
      l4_kernel_clock_t current_tsc = l4_rdtsc();
      l4_kernel_clock_t tsc_diff = current_tsc - _last_ticks_tsc;
      _last_ticks_tsc = current_tsc;

      tsc_diff /= _timer_div.divisor();

      if (_regs.tmr_cur < tsc_diff)
        _regs.tmr_cur = 0;
      else
        _regs.tmr_cur -= tsc_diff;

      if (_regs.tmr_cur == 0)
        {
          if (_timer.masked())
            _timer.pending() = 1;
          else
            irq_trigger(_timer.vector());

          if (_timer.periodic())
            _regs.tmr_cur = _regs.tmr_init;
        }
    }
}

/**
 * Enqueue an interrupt and trigger an IPC in the vCPU.
 *
 * \param irq  Interrupt to inject.
 */
void
Virt_lapic::irq_trigger(l4_uint32_t irq, bool irr)
{
  {
    std::lock_guard<std::mutex> lock(_int_mutex);

    if (irr)
      _regs.irr.set_irq(irq);
    else
      _non_irr_irqs.push(irq);
  }

  _lapic_irq->trigger();
}

int
Virt_lapic::next_pending_irq()
{
  std::lock_guard<std::mutex> lock(_int_mutex);

  if (!_non_irr_irqs.empty())
    {
      unsigned irq = _non_irr_irqs.front();
      _non_irr_irqs.pop();
      return irq;
    }

  auto highest_irr = _regs.irr.get_highest_irq();
  if (highest_irr >= 0)
    {
      auto highest_isr = _regs.isr.get_highest_irq();
      if (highest_irr > highest_isr)
        {
          _regs.isr.set_irq(highest_irr);
          _regs.irr.clear_irq(highest_irr);
          return highest_irr;
        }
    }
  return -1;
}

bool
Virt_lapic::is_irq_pending()
{
  std::lock_guard<std::mutex> lock(_int_mutex);
  return !_non_irr_irqs.empty() || _regs.irr.has_irq();
}

bool
Virt_lapic::read_msr(unsigned msr, l4_uint64_t *value) const
{
  switch (msr)
    {
    case 0x1b: // APIC base, Vol. 3A 10.4.4
      *value = Lapic_access_handler::Mmio_addr | Apic_base_enabled;

      if (_lapic_x2_id == 0)
        *value |= Apic_base_bsp_processor;

      if (_x2apic_enabled)
        *value |= Apic_base_x2_enabled;
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
    case 0x80e:
      // not existent in x2apic mode
      if (!_x2apic_enabled)
        *value = _regs.dfr;
      break;
    case 0x80f: *value = _regs.svr; break;
    case 0x810:
    case 0x811:
    case 0x812:
    case 0x813:
    case 0x814:
    case 0x815:
    case 0x816:
    case 0x817: *value = _regs.isr.get_reg(msr - 0x810); break;
    case 0x818:
    case 0x819:
    case 0x81a:
    case 0x81b:
    case 0x81c:
    case 0x81d:
    case 0x81e:
    case 0x81f: *value = _regs.tmr.get_reg(msr - 0x818); break;
    case 0x820:
    case 0x821:
    case 0x822:
    case 0x823:
    case 0x824:
    case 0x825:
    case 0x826:
    case 0x827: *value = _regs.irr.get_reg(msr - 0x820); break;
    case 0x828: *value = _regs.esr; break;
    case 0x82f: *value = _regs.cmci; break;
    // 0x830 handled by Icr_handler
    case 0x832: *value = _timer.raw; break;
    case 0x833: *value = _regs.therm; break;
    case 0x834: *value = _regs.perf; break;
    case 0x835: *value = _regs.lint[0]; break;
    case 0x836: *value = _regs.lint[1]; break;
    case 0x837: *value = _regs.err; break;
    case 0x838: *value = _regs.tmr_init; break;
    case 0x839: *value = _regs.tmr_cur; break;
    case 0x83e: *value = _timer_div.raw; break;

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
      _x2apic_enabled = value & Apic_base_x2_enabled;
      if (_x2apic_enabled)
        {
          Dbg().printf("------ x2APIC enabled\n");
          // from Intel SDM (October 2017)
          // Logical x2APIC ID = [(x2APIC ID[19:4] « 16) | (1 « x2APIC ID[3:0])]
          _regs.ldr =
            (_lapic_x2_id & 0xffff0) << 16 | 1U << (_lapic_x2_id & 0xf);
        }

      // APIC Base field, Vol. 3A 10.4.4
      if (!((value >> 12) & (Lapic_access_handler::Mmio_addr >> 12)))
        // Vol. 3A 10.4.5
        warn().printf(
          "Relocating the Local APIC Registers is not supported.\n");
      break;
    case 0x6e0:
      {
        std::lock_guard<std::mutex> lock(_tmr_mutex);
        _tsc_deadline = value;

        if (0)
          Dbg()
            .printf("New TSC dealine: 0x%llx (now: 0x%llx) timer status: %x\n",
                    value, l4_rdtsc(), _timer.raw);
        break;
      }
    case 0x803: _lapic_version = value; break;
    case 0x808: _regs.tpr = value; break;
    case 0x80d:
      // not writable in x2apic mode
      if (!_x2apic_enabled)
        _regs.ldr = value;
      break;
    case 0x80e:
      // not existent in x2apic mode; writes by system software only in
      // disabled APIC state; which currently isn't supported. => write ignored
      break;
    case 0x80f: _regs.svr = value; break; // TODO react on APIC SW en/disable
    case 0x80b: // x2APIC EOI
      {
        std::lock_guard<std::mutex> lock(_int_mutex);
        _regs.isr.clear_highest_irq();
      }
      if (value != 0)
        {
          Dbg().printf("WARNING: write to EOI not zero, 0x%llx\n", value);
        }
      break;
    case 0x828: _regs.esr = 0; break;
    case 0x82f: _regs.cmci = value; break;
    // 0x830 handled by Icr_handler
    case 0x832:
      {
        Timer_reg new_timer(value);

        if (   _timer.pending() && !new_timer.masked()
            && _timer.vector() == new_timer.vector())
          irq_trigger(_timer.vector());

        _timer = new_timer;
        break;
      }
    case 0x833: _regs.therm = value; break;
    case 0x834: _regs.perf = value; break;
    case 0x835: _regs.lint[0] = value; break;
    case 0x836: _regs.lint[1] = value; break;
    case 0x837: _regs.err = value; break;
    case 0x838:
      _regs.tmr_init = value;
      _regs.tmr_cur = value;
      if (value == 0)
        _timer.disarm();
      break;
    case 0x83e: _timer_div = value; break;
    case 0x83f:
      Dbg().printf("TODO: self IPI\n");
      break;

    default: return false;
    }

  if (0 && msr != 0x80b)
    Dbg().printf("WARNING: APIC write to 0x%x: 0x%llx\n", msr, value);

  return true;
}

} // namepace Gic

#include "device_factory.h"
#include "guest.h"

namespace {

  struct G : Vdev::Factory
  {
    cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                      Vdev::Dt_node const &) override
    {
      auto apics = devs->vmm()->apic_array();
      auto io_apic = Vdev::make_device<Gic::Io_apic>(apics);
      devs->vmm()->add_mmio_device(io_apic->mmio_region(), io_apic);
      return io_apic;
    }
  };

  static G g;
  static Vdev::Device_type d = {"intel,ioapic", nullptr, &g};

  struct F : Vdev::Factory
  {
    cxx::Ref_ptr<Vdev::Device> create(Vdev::Device_lookup *devs,
                                      Vdev::Dt_node const &) override
    {
      auto apics = devs->vmm()->apic_array();
      auto msix_ctrl = Vdev::make_device<Gic::Msix_control>(apics);
      devs->vmm()->icr_handler()->register_msix_ctrl(msix_ctrl);
      return msix_ctrl;
    }
  };

  static F f;
  static Vdev::Device_type e = {"intel,msi-controller", nullptr, &f};

} // namespace
