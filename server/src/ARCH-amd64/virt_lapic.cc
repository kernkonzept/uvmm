/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2017-2022 Kernkonzept GmbH.
 * Author(s): Philipp Eppelt <philipp.eppelt@kernkonzept.com>
 */

#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/unique_cap>

#include <climits>

#include "debug.h"
#include "virt_lapic.h"
#include "mad.h"
#include "guest.h"


namespace Gic {

using L4Re::chkcap;
using L4Re::chksys;

Virt_lapic::Virt_lapic(unsigned id, cxx::Ref_ptr<Vmm::Cpu_dev> cpu)
: _lapic_irq(chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                    "Allocate local APIC notification IRQ.")),
  _lapic_x2_id(id),
  _lapic_version(Lapic_version),
  _x2apic_enabled(false),
  _nmi_pending(false),
  _cpu(cpu),
  _registry(cpu->vcpu().get_ipc_registry())
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

  _apic_timer = Vdev::make_device<Apic_timer>(this);
}

void
Virt_lapic::set(unsigned irq)
{
  irq_trigger(irq);
}

void
Virt_lapic::set(Vdev::Msix::Data_register_format data)
{
  //  assumption 1: delivery_mode lowest prio already arbitrated
  //  assumption 2: only called if this APIC is destination
  using namespace Vdev::Msix;

  switch (data.delivery_mode())
    {
    case Dm_fixed: // FALL-THROUGH
    case Dm_lowest_prio:
      irq_trigger(data.vector(), true);
      break;
    case Dm_smi: info().printf("SMI dropped at LAPIC 0x%x\n", id()); break;
    case Dm_nmi: nmi(); break;
    case Dm_init: init_ipi(); break;
    case Dm_startup: startup_ipi(data); break;
    case Dm_extint: irq_trigger(data.vector(), false); break;
    default:
      info().printf("LAPIC 0x%x drops unknown MSI. Delivery mode 0x%x, Vector "
                    "0x%x, data: 0x%llx\n",
                    id(), data.delivery_mode().get(), data.vector().get(),
                    data.raw);
      break;
    };
}

void
Virt_lapic::init_ipi()
{
  // Only sleeping vCPUs must be rescheduled
  if (_cpu->get_cpu_state() == Vmm::Cpu_dev::Sleeping)
    _cpu->reschedule();

  _cpu->send_init_ipi();
  _sipi_cnt = 0;
}

void
Virt_lapic::startup_ipi(Vdev::Msix::Data_register_format data)
{
  // only act on the first SIPI
  if (_sipi_cnt++)
    return;

  enum : l4_uint32_t
  {
    Icr_startup_page_shift = 12
  };

  l4_addr_t start_eip = data.vector() << Icr_startup_page_shift;
  start_cpu(start_eip);
  _cpu->send_sipi();
}

void
Virt_lapic::start_cpu(l4_addr_t entry)
{
  Vmm::Vcpu_ptr vcpu = _cpu->vcpu();
  vcpu->r.sp = 0;
  vcpu->r.ip = entry; // r.ip used to communicate entry to Vcpu_ptr.reset()

  info().printf("Starting CPU %u on EIP 0x%lx\n", _lapic_x2_id, entry);
}

void
Virt_lapic::bind_irq_src_handler(unsigned irq, Irq_src_handler *handler)
{
  assert (irq < 256); // sources array length
  // linux writes the same RTE at IOAPIC twice; allow this behavior if the
  // handler stays the same.
  if(handler && _sources[irq] && handler != _sources[irq])
    {
      Err().printf("[LAPIC 0x%x] IRQ src handler for IRQ %u already set to %p, new "
                   "%p\n",
                   _lapic_x2_id, irq, _sources[irq], handler);
      throw L4::Runtime_error(-L4_EEXIST, "Bind IRQ src handler at local APIC.");
    }

  _sources[irq] = handler;
}

Irq_src_handler *
Virt_lapic::get_irq_src_handler(unsigned irq) const
{
  assert (irq < 256); // sources array length
  return _sources[irq];
}

int
Virt_lapic::dt_get_interrupt(fdt32_t const *, int, int *) const
{ return 1; }

void
Virt_lapic::nmi()
{
  _nmi_pending.store(true, std::memory_order_release);
  _lapic_irq->trigger();
}

/**
 * Enqueue an interrupt and trigger an IPC in the vCPU.
 *
 * \param irq  Interrupt to inject.
 */
void
Virt_lapic::irq_trigger(l4_uint32_t irq, bool irr)
{
  bool trigger = true;
  {
    std::lock_guard<std::mutex> lock(_int_mutex);

    if (irr)
      // don't trigger lapic_irq, if the IRR has this IRQ already queued.
      trigger = !_regs.irr.set_irq(irq);
    else
      {
        // don't trigger lapic_irq again, if an IRQ is already queued.
        trigger = _non_irr_irqs.empty();
        _non_irr_irqs.push(irq);
      }
  }

  if (trigger)
    _lapic_irq->trigger();
}

bool
Virt_lapic::next_pending_nmi()
{
  bool expected = true;
  return _nmi_pending.compare_exchange_strong(expected, false,
                                              std::memory_order_acquire,
                                              std::memory_order_relaxed);
}

bool
Virt_lapic::is_nmi_pending()
{ return _nmi_pending.load(std::memory_order_relaxed); }

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
    case Msr_ia32_apic_base: // APIC base, Vol. 3A 10.4.4
      *value = Lapic_access_handler::Mmio_addr | Apic_base_enabled;

      if (_lapic_x2_id == 0)
        *value |= Apic_base_bsp_processor;

      if (_x2apic_enabled)
        *value |= Apic_base_x2_enabled;
      break;
    case Msr_ia32_tsc_deadline:
      *value = _apic_timer->read_tsc_deadline_msr();
      break;
    case Msr_ia32_x2apic_apicid:
      *value = _x2apic_enabled
                 ? _lapic_x2_id
                 : (_lapic_x2_id << Xapic_mode_local_apic_id_shift);
      break;
    case Msr_ia32_x2apic_version: *value = _lapic_version; break;
    case Msr_ia32_x2apic_tpr: *value = _regs.tpr; break;
    case Msr_ia32_x2apic_ppr: *value = _regs.ppr; break;
    case Msr_ia32_x2apic_ldr: *value = _regs.ldr; break;
    case Mmio_apic_destination_format_register:
      // not existent in x2apic mode
      if (!_x2apic_enabled)
        *value = _regs.dfr;
      break;
    case Msr_ia32_x2apic_sivr: *value = _regs.svr; break;
    case 0x810:
    case 0x811:
    case 0x812:
    case 0x813:
    case 0x814:
    case 0x815:
    case 0x816:
    case Msr_ia32_x2apic_isr7:
      *value = _regs.isr.get_reg(msr - 0x810);
      break;
    case 0x818:
    case 0x819:
    case 0x81a:
    case 0x81b:
    case 0x81c:
    case 0x81d:
    case 0x81e:
    case Msr_ia32_x2apic_tmr7:
      *value = _regs.tmr.get_reg(msr - 0x818);
      break;
    case 0x820:
    case 0x821:
    case 0x822:
    case 0x823:
    case 0x824:
    case 0x825:
    case 0x826:
    case Msr_ia32_x2apic_irr7:
      *value = _regs.irr.get_reg(msr - 0x820);
      break;
    case Msr_ia32_x2apic_esr: *value = _regs.esr; break;
    case Msr_ia32_x2apic_lvt_cmci: *value = _regs.cmci; break;
    // 0x830 handled by Icr_handler
    case Msr_ia32_x2apic_lvt_timer:
      *value = _apic_timer->read_lvt_timer_reg();
      break;
    case Msr_ia32_x2apic_lvt_thermal: *value = _regs.therm; break;
    case Msr_ia32_x2apic_lvt_pmi: *value = _regs.perf; break;
    case Msr_ia32_x2apic_lvt_lint0: *value = _regs.lint[0]; break;
    case Msr_ia32_x2apic_lvt_lint1: *value = _regs.lint[1]; break;
    case Msr_ia32_x2apic_lvt_error: *value = _regs.err; break;
    case Msr_ia32_x2apic_init_count:
      *value = _apic_timer->read_tmr_init();
      break;
    case Msr_ia32_x2apic_cur_count: *value = _apic_timer->read_tmr_cur(); break;
    case Msr_ia32_x2apic_div_conf:
      *value = _apic_timer->read_divide_configuration_reg();
      break;

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
    case Msr_ia32_apic_base:
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
    case Msr_ia32_tsc_deadline:
      _apic_timer->write_tsc_deadline_msr(value);
      break;
    case Msr_ia32_x2apic_version: break; // RO register: ignore write
    case Msr_ia32_x2apic_tpr: _regs.tpr = value; break;
    case Msr_ia32_x2apic_ldr:
      // not writable in x2apic mode
      if (!_x2apic_enabled)
        _regs.ldr = value;
      break;
    case Mmio_apic_destination_format_register:
      // not existent in x2apic mode; writes by system software only in
      // disabled APIC state; which currently isn't supported. => write ignored
      break;
    case Msr_ia32_x2apic_sivr:
      _regs.svr = value; break; // TODO react on APIC SW en/disable
    case Msr_ia32_x2apic_eoi:
      {
        std::lock_guard<std::mutex> lock(_int_mutex);
        _regs.isr.clear_highest_irq();
      }
      if (value != 0)
        {
          Dbg().printf("WARNING: write to EOI not zero, 0x%llx\n", value);
        }
      break;
    case Msr_ia32_x2apic_esr: _regs.esr = 0; break;
    case Msr_ia32_x2apic_lvt_cmci: _regs.cmci = value; break;
    // 0x830 handled by Icr_handler
    case Msr_ia32_x2apic_lvt_timer:
      _apic_timer->write_lvt_timer_reg(value);
      break;
    case Msr_ia32_x2apic_lvt_thermal: _regs.therm = value; break;
    case Msr_ia32_x2apic_lvt_pmi: _regs.perf = value; break;
    case Msr_ia32_x2apic_lvt_lint0: _regs.lint[0] = value; break;
    case Msr_ia32_x2apic_lvt_lint1: _regs.lint[1] = value; break;
    case Msr_ia32_x2apic_lvt_error: _regs.err = value; break;
    case Msr_ia32_x2apic_init_count:
      _apic_timer->write_tmr_init(value);
      break;
    case Msr_ia32_x2apic_div_conf:
      _apic_timer->write_divide_configuration_reg(value);
      break;
    case Msr_ia32_x2apic_self_ipi:
      if (_x2apic_enabled)
        irq_trigger(value & 0xff);
      else
        // if X2APIC is not enabled, writing IA32_SELF_IPI incurs a #GP
        return false;
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
