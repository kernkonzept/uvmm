/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2013-2022 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include "debug.h"
#include "gic_cpu.h"
#include "gic_iface.h"

namespace Gic {

template<bool AFF_ROUTING>
class Dist
: public Dist_if,
  public Ic,
  public Monitor::Gic_cmd_handler<Monitor::Enabled, Dist<AFF_ROUTING>>
{
  friend Monitor::Gic_cmd_handler<Monitor::Enabled, Dist<AFF_ROUTING>>;

protected:
  static Dbg trace() { return Dbg(Dbg::Irq, Dbg::Trace, "GICD"); }

public:
  using Irq = Cpu::Irq;

  enum Regs
  {
    CTLR  = 0x000,
    TYPER = 0x004, // RO
    IIDR  = 0x008, // RO
    SGIR  = 0xf00, // WO
  };

  l4_uint32_t ctlr;
  unsigned char tnlines;

  Dist(unsigned tnlines, unsigned max_cpus)
  : ctlr(0), tnlines(tnlines),
    _cpu(max_cpus),
    _spis(tnlines * 32, Cpu::Num_local),
    _prio_mask(0),
    _lpis(nullptr)
  {
  }

  Irq &spi(unsigned spi)
  {
    assert (spi < _spis.size());
    return _spis[spi];
  }

  Irq const &spi(unsigned spi) const
  {
    assert (spi < _spis.size());
    return _spis[spi];
  }

  void register_lpis(Irq_array *lpis)
  {
    // Ensure that once set, the LPI array cannot be changed.
    if (_lpis)
      L4Re::chksys(-L4_EEXIST, "Assigning LPIs to GIC");

    _lpis = lpis;
    for (auto const &cpu : _cpu)
      {
        if (cpu)
          cpu->register_lpis(_lpis);
      }
  }

  Irq &lpi(unsigned lpi)
  {
    assert (_lpis && lpi < _lpis->size());
    return (*_lpis)[lpi];
  }

  Irq const &lpi(unsigned lpi) const
  {
    assert (_lpis && lpi < _lpis->size());
    return (*_lpis)[lpi];
  }


  /// \group Implementation of Ic functions
  /// \{
  void clear(unsigned) override {}

  void bind_irq_src_handler(unsigned irq, Irq_src_handler *handler) override
  {
    Irq &pin = spi(irq - Cpu::Num_local);

    if (handler && pin.get_irq_src_handler())
      L4Re::chksys(-L4_EEXIST, "Assigning IRQ src handler to GIC");

    pin.set_irq_src(handler);
  }

  Irq_src_handler *get_irq_src_handler(unsigned irq) const override
  { return spi(irq - Cpu::Num_local).get_irq_src_handler(); }

  int dt_get_interrupt(fdt32_t const *prop, int propsz, int *read) const override
  {
    enum Irq_types
    {
      Irq_ppi_base = 16,
      Irq_ppi_max = 16,
      Irq_spi_base = 32,
    };

    enum Dts_interrupt_cells
    {
      Irq_cell_type = 0,
      Irq_cell_number = 1,
      Irq_cell_flags = 2,
      Irq_cells = 3
    };

    if (propsz < Irq_cells)
      return -L4_ERANGE;

    int irqnr = fdt32_to_cpu(prop[Irq_cell_number]);

    if (fdt32_to_cpu(prop[Irq_cell_type]) == 0)
      irqnr += Irq_spi_base;
    else
      {
        if (irqnr >= Irq_ppi_max)
          L4Re::chksys(-L4_EINVAL, "Only 16 PPI interrupts allowed");

        irqnr += Irq_ppi_base;
      }

    if (read)
      *read = Irq_cells;

    return irqnr;
  }
  /// \} end of Ic implementation

  /// \group abstract GIC interface for different GIC versions
  /// \{

  /// Setup the CPU interface for the given `vcpu` running on `thread`.
  Cpu *add_cpu(Vmm::Vcpu_ptr vcpu)
  {
    unsigned cpu = vcpu.get_vcpu_id();
    if (cpu >= _cpu.capacity())
      return nullptr;

    // The boot CPU is the sentinel for all CPUs, including itself.
    // Nevertheless a special case for the boot CPU is needed here, because
    // the entry for the boot CPU is not yet set up in the _cpu vector.
    Vmm::Vcpu_ptr sentinel_vcpu = cpu != 0 ? _cpu[0]->vcpu() : vcpu;

    trace().printf("set CPU interface for CPU %02d (%p) to %p\n",
                   cpu, &_cpu[cpu], *vcpu);
    _cpu.set_at(cpu, cxx::make_unique<Cpu>(vcpu, sentinel_vcpu, &_spis));
    Cpu *ret = _cpu[cpu].get();
    ret->register_lpis(_lpis);
    if (cpu == 0)
      {
        _prio_mask = ~((1U << (7 - ret->vtr().pri_bits())) - 1U);

        // Our implementation assumes that there is always a valid
        // Irq::vcpu_handler() for interrupts that can get pending&enabled. To
        // make things easy, all SPIs use the boot CPU as Vcpu_handler
        // sentinel.
        for (unsigned i = 0; i < _spis.size(); i++)
          _spis[i].init_spi(ret);
      }

    return ret;
  }

  /// write to the GICD_CTLR.
  virtual void write_ctlr(l4_uint32_t val)
  {
    ctlr = val;
  }

  /// read to the GICD_TYPER.
  virtual l4_uint32_t get_typer() const
  {
    return tnlines | (static_cast<l4_uint32_t>(_cpu.size() - 1) << 5);
  }

  /// read to the CoreSight IIDRs.
  virtual l4_uint32_t iidr_read(unsigned offset) const = 0;
  /// \}

  Cpu *cpu(unsigned id)
  { return id < _cpu.capacity() ? _cpu[id].get() : nullptr; }

protected:
  /**
   * Check targets of SPIs and possibly divert them to a different vCPU.
   *
   * When affinity routing is not used the target vCPU of a SPI might change
   * if the set of online vCPUs changes.
   */
  void retarget_spis()
  {
    if (AFF_ROUTING)
      return;

    std::lock_guard<std::mutex> lock(_target_lock);
    for (unsigned i = 0; i < _spis.size(); i++)
      {
        Irq &irq = _spis[i];
        unsigned vcpu = find_cpu_for_target(irq.target());
        if (vcpu != irq.cpu())
          irq.target(irq.target(), cpu(vcpu));
      }
  }

private:
  /**
   * Get the first usable vCPU number from the given GICD_ITARGETSRn field.
   *
   * Might be Irq::Invalid_cpu if the irq targets no CPU or only offline CPUs.
   */
  unsigned find_cpu_for_target(unsigned char tgt)
  {
    while (tgt)
      {
        unsigned first = __builtin_ffs(tgt) - 1;
        if (first >= _cpu.capacity())
          return Irq::Invalid_cpu;

        Vcpu_handler *cpu = _cpu[first].get();
        if (cpu && cpu->online())
          return first;

        tgt &= ~(1U << first);
      }

    return Irq::Invalid_cpu;
  }

  /// \group Per IRQ register interfaces
  /// \{
  enum Reg_group_idx
  {
    R_group = 0,
    R_isenable,
    R_icenable,
    R_ispend,
    R_icpend,
    R_isactive,
    R_icactive,
    R_prio,
    R_target,
    R_cfg,
    R_grpmod,
    R_nsacr,
    R_route
  };

  l4_uint32_t irq_mmio_read(Irq const &irq, unsigned rgroup)
  {
    switch (rgroup)
      {
      case R_group:    return irq.group();
      case R_isenable:
      case R_icenable: return irq.enabled();
      case R_ispend:
      case R_icpend:   return irq.pending();
      case R_isactive:
      case R_icactive: return irq.active();
      case R_prio:     return irq.prio();
      case R_target:   return AFF_ROUTING ? 0 : irq.target();
      case R_cfg:      return irq.config();
      case R_grpmod:   return 0;
      case R_nsacr:    return 0;
      default:         assert (false); return 0;
      }
  }

  void irq_mmio_write(Irq &irq, unsigned rgroup, l4_uint32_t value)
  {
    switch (rgroup)
      {
      case R_group:    irq.group(value);               return;
      case R_isenable:
        if (value)
          {
            Vcpu_handler *dest_cpu = irq.enable(true);
            if (dest_cpu)
              dest_cpu->notify_irq();
          }
          return;
      case R_icenable:
        if (value)
          irq.enable(false);
        return;
      case R_ispend:
        if (value)
          {
            Vcpu_handler *dest_cpu = irq.pending(true);
            if (dest_cpu)
              dest_cpu->notify_irq();
          }
          return;
      case R_icpend:
        if (value)
          irq.pending(false);
        return;
      case R_isactive:
        if (value)
          irq.active(true);
        return;
      case R_icactive:
        if (value)
          irq.active(false);
        return;
      case R_prio:     irq.prio(value & _prio_mask);   return;
      case R_target:
        if (!AFF_ROUTING && irq.id() >= Cpu::Num_local)
          {
            std::lock_guard<std::mutex> lock(_target_lock);
            irq.target(value, cpu(find_cpu_for_target(value)));
          }
        return;
      case R_cfg:      irq.config(value);              return;
      case R_grpmod:   /* GICD_CTRL.DS=1 -> RAZ/WI */  return;
      case R_nsacr:    /* GICD_CTRL.DS=1 -> RAZ/WI */  return;
      default:         assert (false);                 return;
      }
  }
  /// \} end of per IRQ registers

  /**
   * Helper to demux multiple IRQs-per register accesses.
   * \note Local IRQs vs SPIs must be resolved already.
   */
  template<unsigned SHIFT, typename OP>
  void _demux_irq_reg(Irq_array &irqs,
                      unsigned s, unsigned n,
                      unsigned reg, OP &&op)
  {
    unsigned const rshift = 8 >> SHIFT;
    l4_uint32_t const mask = 0xff >> (8 - rshift);
    for (unsigned x = 0; x < n; ++x)
      {
        unsigned const i = x + s;
        op(irqs[i], reg, mask, rshift * x);
      }
  }

  /**
   * Helper to demux multiple IRQs-per register accesses.
   * \note Local IRQs vs SPIs must be resolved already.
   */
  template<unsigned SHIFT, typename OP>
  void _demux_irq_reg(unsigned reg, unsigned offset,
                      unsigned size,
                      unsigned cpu_id, OP &&op)
  {
    unsigned const irq_s = (offset & (~0U) << size) << SHIFT;
    unsigned const nirq = (1 << size) << SHIFT;

    if (irq_s < Cpu::Num_local)
      _demux_irq_reg<SHIFT>(_cpu[cpu_id]->local_irqs(), irq_s, nirq, reg, op);
    else if (irq_s - Cpu::Num_local < _spis.size())
      _demux_irq_reg<SHIFT>(_spis, irq_s - Cpu::Num_local, nirq, reg, op);
  }

  /**
   * Helper to demux a complete range of multi IRQ registers with
   * equal number of IRQs per register (given by SHIFT).
   * \pre `reg` >= `START`
   * \retval false if `reg` >= END
   * \retval true if `reg` < END;
   */
  template<unsigned BLK, unsigned START, unsigned END,
           unsigned SHIFT, typename OP>
  bool _demux_irq_block(unsigned reg, unsigned size, unsigned cpu_id, OP &&op)
  {
    unsigned const rsh = 10 - SHIFT;
    static_assert((START & ((1U << rsh) - 1)) == 0U, "low bits of START zero");
    static_assert((END   & ((1U << rsh) - 1)) == 0U, "low bits of END zero");
    if (reg < END)
      {
        unsigned const x = reg >> rsh;
        _demux_irq_reg<SHIFT>(x - (START >> rsh) + BLK,
                              reg & ~((~0U) << rsh), size, cpu_id, op);
        return true;
      }
    return false;
  }

  /**
   * Demux the access to the whole multi-IRQ register range of the
   * GIC distributor.
   */
  template<typename OP>
  bool _demux_per_irq(unsigned reg, unsigned size, unsigned cpu_id, OP &&op)
  {
    if (reg < 0x80)
      return false;

    if (_demux_irq_block<R_group, 0x80, 0x400, 3>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_prio, 0x400, 0xc00, 0>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_cfg,  0xc00, 0xe00, 2>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_grpmod, 0xd00, 0xd80, 3>(reg, size, cpu_id, op))
      return true;

    if (_demux_irq_block<R_nsacr, 0xe00, 0xf00, 2>(reg, size, cpu_id, op))
      return true;

    return false;
  }

  /**
   * Helper to access the IIDR register range of CoreSight GICs
   * This helper forwards to the iidr_read interface.
   * \retval true if `reg` is in the IIDR range of the device.
   * \retval false otherwise
   */
  bool _iidr_try_read(unsigned reg, char size, l4_uint64_t *val)
  {
    if (size == 2 && reg >= 0xffd0 && reg <= 0xfffc)
      {
        *val = iidr_read(reg - 0xffd0);
        return true;
      }

    return false;
  }

  /**
   * Helper for reads in the GICD header area 0x00 - 0x10
   */
  l4_uint32_t _read_gicd_header(unsigned reg)
  {
    unsigned r = reg >> 2;
    switch (r)
      {
      case 0: return ctlr;        // GICD_CTRL
      case 1: return get_typer(); // GICD_TYPER
      case 2: return 0x43b;       // GICD_IIDR
      default: break;             // includes GICD_TYPER2
      }
    return 0;
  }

protected:

  /**
   * Read a register in the multi IRQs register range of GICD.
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   */
  bool
  read_multi_irq(unsigned reg, char size, unsigned cpu_id, l4_uint64_t *res)
  {
    auto rd = [this,res](Irq const &irq, unsigned r, l4_uint32_t mask,
                        unsigned shift)
      {
        *res |= (this->irq_mmio_read(irq, r) & mask) << shift;
      };

    return _demux_per_irq(reg, size, cpu_id, rd);
  }

  /**
   * Write a register in the multi IRQs register range of GICD.
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   */
  bool
  write_multi_irq(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    auto wr = [this,value](Irq &irq, unsigned r, l4_uint32_t mask,
                           unsigned shift)
      {
        this->irq_mmio_write(irq, r, (value >> shift) & mask);
      };

    return _demux_per_irq(reg, size, cpu_id, wr);
  }

  /**
   * Read for generic GICD registers.
   *
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   *
   * This function is a helper for specific GICD mmio read implementations.
   */
  bool dist_read(unsigned reg, char size, unsigned cpu_id, l4_uint64_t *res)
  {
    if (reg < 0x10) // GICD_CTRL..GICD_TYPER2
      {
        *res = _read_gicd_header(reg);
        return true;
      }

    if (reg == 0x10) // GICD_STATUS
      {
        *res = 0;
        return true;
      }

    if (reg < 0x80) // < GICD_IGROUPR
      return true;

    if (read_multi_irq(reg, size, cpu_id, res))
      return true;

    return _iidr_try_read(reg, size, res);
  }

  /**
   * Write for generic GICD registers.
   *
   * \retval true  if `reg` is handled by the function.
   * \retval false otherwise.
   *
   * This function is a helper for specific GICD mmio write implementations.
   */
  bool dist_write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    if (reg == 0 && size == 2)
      {
        write_ctlr(value);
        return true;
      }

    if (reg < 0x80) // < GICD_IGROUPR
      return true; // all RO, WI, WO or not implemented

    return write_multi_irq(reg, size, value, cpu_id);
  }

protected:
  Cpu_vector _cpu;
  Irq_array _spis;
  l4_uint8_t _prio_mask;

  /**
   * Protect IRQ migration calls from concurrent invocations.
   *
   * IRQ migration is not thread safe. See Irq::target() for details. Also
   * Dist_v3::_router must be kept in sync. Because migrations should happen
   * rarely, a single lock for all Irqs should suffice.
   */
  std::mutex _target_lock;

  Irq_array *_lpis;
};

}
