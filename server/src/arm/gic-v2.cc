/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "gic.h"
#include "gic_mixin.h"
#include "guest.h"
#include "mem_types.h"

namespace {
using namespace Gic;

/**
 * GICv2 Distributor implementation.
 */
class Dist_v2 : public Dist_mixin<Dist_v2>
{
private:
  using Dist = Dist_mixin<Dist_v2>;
  unsigned char _active_grp0_cpus = 0;
  unsigned char _active_grp1_cpus = 0;

public:

  /// SGIR implemenation
  struct Sgir
  {
  private:
    l4_uint32_t _raw;

  public:
    explicit Sgir(l4_uint32_t val) : _raw(val) {}
    l4_uint32_t raw() const { return _raw; }

    CXX_BITFIELD_MEMBER(24, 25, target_list_filter, _raw);
    CXX_BITFIELD_MEMBER(16, 23, cpu_target_list, _raw);
    CXX_BITFIELD_MEMBER(15, 15, nsatt, _raw);
    CXX_BITFIELD_MEMBER( 0,  3, sgi_int_id, _raw);
  };

  /// GICv2 has per source CPU SGI pending bits per CPU
  static bool sgi_pend_regs() { return true; }

  /// GICv2 specific vGIC list register (LR) access
  struct Cpu_if
  {
    using Lr = Vmm::Arm::Gic_h::Lr;
    static Lr read_lr(Vmm::Vcpu_ptr vcpu, unsigned idx)
    {
      return Lr(l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_GIC_V2_LR0 + idx * 4));
    }

    static void write_lr(Vmm::Vcpu_ptr vcpu, unsigned idx, Lr lr)
    { l4_vcpu_e_write_32(*vcpu, L4_VCPU_E_GIC_V2_LR0 + idx * 4, lr.raw); }

    static unsigned pri_mask(Vmm::Vcpu_ptr vcpu)
    {
      l4_uint32_t v = l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_GIC_VMCR);
      return (v >> 24) & 0xf8;
    }
  };

  /// create a GICv2 instance
  Dist_v2(unsigned tnlines) : Dist(tnlines, 8) {}

  void setup_cpu(Vmm::Vcpu_ptr vcpu, L4::Cap<L4::Thread> thread) override
  {
    auto *c = Dist::add_cpu(vcpu, thread);
    if (!c)
      return;

    unsigned id = vcpu.get_vcpu_id();
    for (unsigned i = 0; i < 32; ++i)
      c->local_irq(i).target(1u << id);
  }

  /// setup the mappings for a GICv2 distributor and CPU interface in the VM
  cxx::Ref_ptr<Vdev::Device>
  setup_gic(Vdev::Device_lookup *devs, Vdev::Dt_node const &node) override
  {
    cxx::Ref_ptr<Dist_v2> self(this);
    // attach GICD to VM
    devs->vmm()->register_mmio_device(self, Vmm::Region_type::Virtual, node);
    // attach GICC to VM
    devs->vmm()->map_gicc(devs, node);

    node.setprop_string("compatible", "arm,gic-400");
    return self;
  }

  /// keep active group CPUs up to date (if guest disables IRQs on a CPU interface)
  void update_gicc_state(Vmm::Arm::Gic_h::Misr misr, unsigned current_cpu)
  {
    if (misr.grp0_e())
      __atomic_or_fetch(&_active_grp0_cpus, (1UL << current_cpu), __ATOMIC_SEQ_CST);

    if (misr.grp0_d())
      __atomic_and_fetch(&_active_grp0_cpus, ~(1UL << current_cpu), __ATOMIC_SEQ_CST);

    if (misr.grp1_e())
      __atomic_or_fetch(&_active_grp1_cpus, (1UL << current_cpu), __ATOMIC_SEQ_CST);

    if (misr.grp1_d())
      __atomic_and_fetch(&_active_grp1_cpus, ~(1UL << current_cpu), __ATOMIC_SEQ_CST);
  }

  /// helper to send a notification to a group of CPUs
  void notify_cpus(unsigned targets) const
  {
    unsigned const cpus = _cpu.size();
    for (unsigned cpu = 0; cpu < cpus && targets; ++cpu, targets >>= 1)
      if ((targets & 1) && (cpu != vmm_current_cpu_id))
        _cpu[cpu]->notify();
  }

  /**
   * Inject a CPU local IRQ.
   * \pre `id` < 32
   */
  void inject_local(unsigned id, unsigned current_cpu)
  {
    Cpu *cpu = _cpu[current_cpu].get();
    Irq const &irq = cpu->local_irq(id);
    if (irq.pending(true))
      {
        // need to take some action to pass IRQ to a CPU
        unsigned char current = 1 << current_cpu;
        unsigned char active_mask = irq.group()
                                  ? cxx::access_once(&_active_grp1_cpus)
                                  : cxx::access_once(&_active_grp0_cpus);
        if ((current & active_mask) && cpu->inject<Cpu_if>(irq, id))
          return;
      }
  }

  /**
   * Inject an SPI.
   * \pre `id` >= 32
   */
  void inject_irq(Irq const &irq, unsigned id, unsigned current_cpu)
  {
    if (irq.pending(true))
      {
        // need to take some action to pass IRQ to a CPU
        unsigned char current = 1 << current_cpu;
        unsigned char active_mask = irq.group()
                                  ? cxx::access_once(&_active_grp1_cpus)
                                  : cxx::access_once(&_active_grp0_cpus);
        if ((irq.target() & current & active_mask))
          {
            if (_cpu[current_cpu]->inject<Cpu_if>(irq, id))
              return;
          }
        else
          {
            if (0)
              printf("Cpu%d - %s:Warn: IRQ %d for different CPU: %x & %x & %x\n"
                     "\tirq.group() = %x ? %d : %d\n",
                     vmm_current_cpu_id, __PRETTY_FUNCTION__, id,
                     irq.target(), current, active_mask,
                     irq.group(), _active_grp1_cpus, _active_grp0_cpus);
          }
        if (unsigned char map = (irq.target() & ~current & active_mask))
          notify_cpus(map);
      }
  }

  /**
   * Set `irq` pending.
   */
  void set(unsigned irq) override
  {
    if (irq < Cpu::Num_local)
      inject_local(irq, vmm_current_cpu_id);
    else
      inject_irq(this->spi(irq - Cpu::Num_local), irq, vmm_current_cpu_id); // SPI
  }

  /// find a pending SPI with prio < pmask.
  int find_pending_spi(unsigned pmask, unsigned target, Irq *irq)
  {
    return _spis.find_pending_irq(pmask, irq, [target](Irq_info const *i)
        {
          return i->target() & (1u << target);
        });
  }

  /// MMIO write to the GICD_SGIR
  void sgir_write(l4_uint32_t value)
  {
    Sgir sgir(value);
    unsigned long targets = 0;
    switch (sgir.target_list_filter())
      {
      case 0:
        targets = sgir.cpu_target_list();
        break;
      case 1:
        targets = ~(1UL << vmm_current_cpu_id);
        break;
      case 2:
        // Since "case 0" could target the local cpu too we do not
        // handle this case seperately
        targets = 1UL << vmm_current_cpu_id;
        break;
      case 3:
        // reserved value
        return;
      default:
        assert(0);
      }

    unsigned irq = sgir.sgi_int_id();
    unsigned cpus = _cpu.size();
    for (unsigned cpu = 0; cpu < cpus && targets; ++cpu, targets >>= 1)
      if (targets & 1)
        {
          if (cpu != vmm_current_cpu_id)
            _cpu[cpu]->ipi(irq);
          else
            inject_local(irq, vmm_current_cpu_id);
        }
  }

  /// MMIO read to GICD registers
  l4_uint64_t read(unsigned reg, char size, unsigned cpu_id)
  {
    l4_uint64_t res = 0;
    if (dist_read(reg, size, cpu_id, &res))
      return res;

    if (reg >= 0xf10 && reg < 0xf30)
      return _cpu[cpu_id]->read_sgi_pend((reg >> 2) & 3);

    return 0;
  }

  /// Read a CoreSight IIDR
  l4_uint32_t iidr_read(unsigned r) const override
  {
    if (r == 0x18)
      return 2 << 4; // GICv2

    return 0;
  }

  /// MMIO write to GICD registers
  void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
  {
    if (dist_write(reg, size, value, cpu_id))
      return;

    unsigned r = reg & ~3;
    if (r == SGIR)
      sgir_write(value);
    else if (r >= 0xf10 && r < 0xf20)
      _cpu[cpu_id]->write_clear_sgi_pend((r - 0xf10) / 4, value);
    else if (r >= 0xf20 && r < 0xf40)
      _cpu[cpu_id]->write_set_sgi_pend((r - 0xf20) / 4, value);
    else
      Dbg(Dbg::Mmio, Dbg::Warn, "Dist")
        .printf("Ignoring write access to %x, %x\n", r, value);
  }
};

struct DF : Dist::Factory
{
  DF() : Factory(2) {}
  cxx::Ref_ptr<Dist_if> create(unsigned tnlines) const
  {
    return Vdev::make_device<Dist_v2>(tnlines);
  }
};

static DF df;

}
