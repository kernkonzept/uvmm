/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2013-2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#pragma once

#include <l4/sys/l4int.h>
#include <l4/cxx/bitfield>
#include <l4/cxx/ref_ptr>
#include <l4/cxx/unique_ptr>
#include <l4/cxx/utils>

#include <cassert>
#include <cstdio>

#include "debug.h"
#include "gic_iface.h"
#include "mmio_device.h"
#include "irq.h"
#include "vcpu_ptr.h"

#include "monitor/gic_cmd_handler.h"

extern __thread unsigned vmm_current_cpu_id;

namespace Gic {

class Irq_info
{
private:
  template<bool T, typename V>
  friend class Monitor::Gic_cmd_handler;

  using State = l4_uint32_t;
  State _state = 0;

public:
  CXX_BITFIELD_MEMBER_RO( 0,  0, pending,     _state); // GICD_I[SC]PENDRn
  CXX_BITFIELD_MEMBER_RO( 1,  1, active,      _state); // GICD_I[SC]ACTIVERn
  CXX_BITFIELD_MEMBER_RO( 3,  3, enabled,     _state); // GICD_I[SC]ENABLERn
  CXX_BITFIELD_MEMBER_RO( 4, 11, cpu,         _state);

  CXX_BITFIELD_MEMBER_RO(12, 19, target,      _state); // GICD_ITARGETSRn ...
  CXX_BITFIELD_MEMBER_RO(20, 27, prio,        _state); // GICD_IPRIORITYRn
  CXX_BITFIELD_MEMBER_RO(28, 29, config,      _state); // GICD_ICFGRn
  CXX_BITFIELD_MEMBER_RO(30, 30, group,       _state); // GICD_IGROUPRn

private:
  template<typename BFM, typename STATET, typename VALT>
  static bool atomic_set(STATET *state, VALT v)
  {
    State old = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    State nv;
    do
      {
        nv = BFM::set_dirty(old, v);
        if (old == nv)
          return false;
      }
    while (!__atomic_compare_exchange_n(state, &old, nv,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return true;
  }

  enum
  {
    Pending_and_enabled = pending_bfm_t::Mask | enabled_bfm_t::Mask,
    Pecpu_mask = Pending_and_enabled | cpu_bfm_t::Mask,
  };

  static State is_pending_and_enabled(State state)
  { return (state & Pending_and_enabled) == Pending_and_enabled; }

  static State is_pending_or_enabled(State state)
  { return state & Pending_and_enabled; }

  Irq_info(Irq_info const &) = delete;
  Irq_info operator = (Irq_info const &) = delete;

  /**
   * Set the enabled bit and conditionally the new_pending bit if
   * the irq was already pending.
   * \return true if we made a new IRQ pending.
   */
  bool set_pe(unsigned char set)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    do
      {
        if (old & set)
          return false;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, old | set,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return is_pending_or_enabled(old);
  }

  /**
   * Clear the enabled and the new_pending flag
   * \return true if the IRQ was disabled and previously new_pending.
   */
  bool clear_pe(unsigned char clear)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    do
      {
        if (!(old & clear))
          return false;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, old & ~clear,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return is_pending_and_enabled(old);
  }

public:
  Irq_info() = default;

  l4_uint32_t state() const
  { return _state; }

  bool enable()
  { return set_pe(enabled_bfm_t::Mask); }

  bool disable()
  { return clear_pe(enabled_bfm_t::Mask); }

  bool set_pending()
  { return set_pe(pending_bfm_t::Mask); }

  bool clear_pending()
  { return clear_pe(pending_bfm_t::Mask); }

  bool take_on_cpu(unsigned char cpu, unsigned char min_prio)
  {
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    State nv;
    do
      {
        State current = cpu_bfm_t::get(old);
        if (current != 0)
          {
            if (current != cpu + 1U)
              return false; // another CPU is currently owning this IRQ

            nv = old;
          }
        else
          nv = old | cpu_bfm_t::val_dirty(cpu + 1);

        if (!is_pending_and_enabled(old))
          return false; // not pending / enabled (any more) skip

        if (prio_bfm_t::get(old) >= min_prio)
          return false; // prio < PMR -> skip

        nv = (nv & ~pending_bfm_t::Mask) | active_bfm_t::Mask;
      }
    while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return true;
  }

  bool eoi(unsigned char cpu, bool pending)
  {
    (void)cpu;
    assert (this->cpu() == cpu + 1);

    // ok, the assumption is that this IRQ is on CPU cpu
    // and we are currently running on CPU cpu, so this
    // this->cpu() cannot change here
    State mask = pending ? ~active_bfm_t::Mask
                         : ~(cpu_bfm_t::Mask | active_bfm_t::Mask);
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    while (!__atomic_compare_exchange_n(&_state, &old,
                                        old & mask,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
      ;
    return false;
  }

  void kick_from_cpu(unsigned char cpu)
  {
    (void)cpu;
    assert (this->cpu() == cpu + 1);
    // ok, the assumption is that this IRQ is on CPU cpu
    // and we are currently running on CPU cpu, so this
    // this->cpu() cannot change here
    State old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
    while (!__atomic_compare_exchange_n(&_state, &old,
                                        (old & ~cpu_bfm_t::Mask) | pending_bfm_t::Mask,
                                        true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
      ;
  }

  bool prio(unsigned char p)
  { return atomic_set<prio_bfm_t>(&_state, p); }

  bool active(bool a)
  { return atomic_set<active_bfm_t>(&_state, a); }

  bool group(bool grp1)
  { return atomic_set<group_bfm_t>(&_state, grp1); }

  bool config(unsigned cfg)
  { return atomic_set<config_bfm_t>(&_state, cfg); }

  bool target(unsigned char tgt)
  { return atomic_set<target_bfm_t>(&_state, tgt); }

  template<typename TGT_MATCH>
  bool is_ready(unsigned min_prio, TGT_MATCH &&tgt_match) const
  {
    return ((_state & Pecpu_mask) == Pending_and_enabled)
           && (prio() < min_prio)
           && tgt_match(this);
  }
};

class Irq_array
{
private:
  using Per_irq_info = Irq_info;

  struct Context
  {
    Eoi_handler *eoi;
    /*
     * Keeps track of the used lr, uses 0 for "no link register
     * assigned" (see #get_empty_lr())
     */
    unsigned char lr;
    Context() : eoi(nullptr), lr(0) {}
  };

  cxx::unique_ptr<Per_irq_info[]> _pending;
  cxx::unique_ptr<Context[]> _irq;
  unsigned _size;

public:
  class Const_irq
  {
    template<bool T, typename V>
    friend class Monitor::Gic_cmd_handler;

  public:
    Const_irq() = default;
    l4_uint32_t state() const { return _p->state(); }
    bool enabled() const { return _p->enabled(); }
    bool pending() const { return _p->pending(); }
    bool active() const { return _p->active(); }
    bool group() const { return _p->group(); }
    unsigned char config() const { return _p->config(); }
    unsigned char prio() const { return _p->prio(); }
    unsigned char target() const { return _p->target(); }

    void do_eoi() const { if (_c->eoi) _c->eoi->eoi(); }
    Eoi_handler *get_eoi_handler() const { return _c->eoi; }

    unsigned cpu() const { return _p->cpu(); }
    unsigned lr() const { return _c->lr; }

    Const_irq &operator ++ () { ++_c; ++_p; return *this; }

    bool operator == (Const_irq const &r) const { return _p == r._p; }
    bool operator != (Const_irq const &r) const { return _p != r._p; }

  protected:
    friend class Irq_array;
    Const_irq(Per_irq_info *p, Context *c) : _p(p), _c(c) {}

    Per_irq_info *_p;
    Context *_c;
  };

  class Irq : public Const_irq
  {
  public:
    Irq() = default;

    void set_eoi(Eoi_handler *eoi) { _c->eoi = eoi; }
    bool enable(bool ena) const
    {
      if (ena)
        return _p->enable();
      else
        return _p->disable();
    }

    using Const_irq::pending;
    bool pending(bool pend) const
    {
      if (pend)
        return _p->set_pending();
      else
        return _p->clear_pending();
    }

    bool take_on_cpu(unsigned char cpu, unsigned char min_prio) const
    {
      return _p->take_on_cpu(cpu, min_prio);
    }

    void kick_from_cpu(unsigned char cpu)
    {
      return _p->kick_from_cpu(cpu);
    }


    using Const_irq::prio;
    void prio(unsigned char p) const { _p->prio(p); }
    bool eoi(unsigned cpu, bool pending) const { return _p->eoi(cpu, pending); }
    using Const_irq::active;
    void active(bool act) const { _p->active(act); }
    using Const_irq::group;
    void group(bool grp1) const { _p->group(grp1); }
    using Const_irq::config;
    void config(unsigned char cfg) const { _p->config(cfg); }

    void set_lr(unsigned idx) const { _c->lr = idx; }
    void clear_lr() const { set_lr(0); }

    using Const_irq::target;
    bool target(unsigned char tgt) const  { return _p->target(tgt); }

    Irq &operator ++ () { ++_c; ++_p; return *this; }


  private:
    friend class Irq_array;
    Irq(Per_irq_info *p, Context *c) : Const_irq(p, c) {}
  };


  explicit Irq_array(unsigned irqs)
  : _size(irqs)
  {
    _pending = cxx::unique_ptr<Per_irq_info[]>(new Per_irq_info[irqs]);
    _irq     = cxx::unique_ptr<Context[]>(new Context[irqs]);
  }

  Irq operator [] (unsigned i)
  { return Irq(_pending.get() + i, _irq.get() + i); }

  Const_irq operator [] (unsigned i) const
  { return Const_irq(_pending.get() + i, _irq.get() + i); }

  unsigned size() const { return _size; }

  template<typename TGT_MATCH>
  int find_pending_irq(unsigned char min_prio, Irq *irq, TGT_MATCH &&tgt_match)
  {
    int hp_irq = -1;
    unsigned char hprio = min_prio;

    for (Per_irq_info *p = _pending.get(); p != _pending.get() + _size; ++p)
      {
        if (!p->is_ready(hprio, tgt_match))
          continue;

        // found a potential victim
        hp_irq = p - _pending.get();
        hprio = p->prio();
      }

    if (hp_irq >= 0)
      *irq = (*this)[hp_irq];

    return hp_irq;
  }

};

///////////////////////////////////////////////////////////////////////////////
// GIC CPU interface
class Cpu
{
  template<bool T, typename V>
  friend class Monitor::Gic_cmd_handler;

public:
  using Irq = typename Irq_array::Irq;
  using Const_irq = typename Irq_array::Const_irq;

  enum { Num_local = 32 };
  enum { Num_lrs = 4 };

  static_assert(Num_lrs <= 32, "Can only handle up to 32 list registers.");

  Cpu(Vmm::Vcpu_ptr vcpu, Irq_array *spis, L4::Cap<L4::Thread> thread)
  : _local_irq(Num_local)
  {
    memset(&_sgi_pend, 0, sizeof(_sgi_pend));
    _cpu_irq = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                            "allocate vcpu notification interrupt");
    L4Re::chksys(L4Re::Env::env()->factory()->create(_cpu_irq.get()),
                 "create vcpu notification interrupt");
    L4Re::chksys(_cpu_irq->bind_thread(thread, 0));

    _vcpu = vcpu;
    _spis = spis;
  }

  /// Get the number of CPU local IRQs
  static unsigned num_local() { return Num_local; }

  /// Get if this is a valid CPU interface (with a vCPU.
  bool is_valid() const { return *_vcpu; }

  /**
   * Get the Processor_Number + Affinity_Value of GICv3+ GICR_TYPER.
   *
   * If this his not a valid CPU interface affinity willbe 0xffffffff.
   */
  l4_uint64_t get_typer() const
  {
    if (is_valid())
      return (((l4_uint64_t)_vcpu.get_vcpu_id()) << 8)
             | (((l4_uint64_t)affinity()) << 32);

    return 0xffffffff00000000;
  }

  /// get the local IRQ for irqn (irqn < 32)
  Irq local_irq(unsigned irqn) { return _local_irq[irqn]; }
  /// get the array of local IRQs of this CPU
  Irq_array &local_irqs() { return _local_irq; }

  /*
   * Get empty list register
   *
   * \return Returns 0 if no empty list register is available, (lr_idx
   *         + 1) otherwise
   */
  unsigned get_empty_lr() const
  { return __builtin_ffs(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_ELSR)); }

  /// return if there are pending IRQs in the LRs
  bool pending_irqs() const
  { return l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_ELSR) != (1ULL << Num_lrs) - 1; }

  /// Get in Irq for the given `intid`, works for SGIs, PPIs, and SPIs
  Irq irq_from_intid(unsigned intid)
  {
    if (intid < Num_local)
      return _local_irq[intid];
    else
      return (*_spis)[intid - Num_local];
  }

  /// Get the associated vCPU
  Vmm::Vcpu_ptr vcpu() const { return _vcpu; }

  /**
   * Set a GICv2 SGI pending and notify this vCPU.
   * \pre `irq` < 16.
   */
  void ipi(unsigned irq)
  {
    if (set_sgi(irq))
      notify();
  }

  /// Send an internal notification to this vCPU.
  void notify()
  { _cpu_irq->trigger(); }

  /// Read GICv2 GICD_[SC]PENDSGIR<reg>
  l4_uint32_t read_sgi_pend(unsigned reg)
  { return _sgi_pend[reg]; }

  /// Write GICv2 GICD_SPENDSGIR<reg>
  void write_set_sgi_pend(unsigned reg, l4_uint32_t value);
  /// Write GICv2 GICD_CPENDSGIR<reg>
  void write_clear_sgi_pend(unsigned reg, l4_uint32_t value);

  /// Handle pending EOIs
  template<typename CPU_IF>
  void handle_eois();

  /// Handle pending GICv2 SGIs
  template<typename GIC_IMPL>
  void handle_ipis();

  /// Add a pending IRQ into a list register (LR).
  template<typename CPU_IF>
  bool add_pending_irq(unsigned lr, Irq const &irq, unsigned irq_id,
                       unsigned src_cpu = 0);

  /// Try to inject an SPI on this CPU
  template<typename CPU_IF>
  bool inject(Irq const &irq, unsigned irq_id, unsigned src_cpu = 0);

  /// Handle pending vGIC maintenance IRQs
  template<typename CPU_IF>
  void handle_maintenance_irq(unsigned /*current_cpu*/)
  { handle_eois<CPU_IF>(); }

  /// Find a pending SGI (not on GICv2) or PPI
  int find_pending_irq(unsigned char min_prio, Irq *irq)
  {
    return _local_irq.find_pending_irq(min_prio, irq,
                                       [](void const *){return true;});
  }

  /**
   * Set a GICv2 SGI for this CPU pending
   * \pre `irq` < 16.
   */
  bool set_sgi(unsigned irq);

  /**
   * Clear a pending GICv2 SGI from `src` on this CPU.
   * \pre `irq` < 16.
   */
  void clear_sgi(unsigned irq, unsigned src);

  /**
   * Dump GICv2 SGI state.
   */
  void dump_sgis() const;

  /// read GICV_HCR / ICH_HCR_EL2
  Vmm::Arm::Gic_h::Hcr hcr() const
  {
    using Vmm::Arm::Gic_h::Hcr;
    return Hcr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_HCR));
  }

  /// write GICV_HCR / ICH_HCR_EL2
  void write_hcr(Vmm::Arm::Gic_h::Hcr hcr) const
  { l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_GIC_HCR, hcr.raw); }

  /// read GICV_MISR / ICH_MISR_EL2
  Vmm::Arm::Gic_h::Misr misr() const
  {
    using Vmm::Arm::Gic_h::Misr;
    return Misr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_MISR));
  }

  /// read GICH_VTR / ICH_VTR_EL2
  Vmm::Arm::Gic_h::Vtr vtr() const
  {
    using Vmm::Arm::Gic_h::Vtr;
    return Vtr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_VTR));
  }

  /**
   * Get the affinity from the vCPU MPIDR.
   * \pre the CPU interface must be initialized (see initialize()).
   */
  l4_uint32_t affinity() const
  {
    l4_uint64_t mpidr = l4_vcpu_e_read(*_vcpu, L4_VCPU_E_VMPIDR);
    return (mpidr & 0x00ffffff) | ((mpidr >> 8) & 0xff000000);
  }

private:
  /// GICv2 SGI pending registers
  l4_uint32_t _sgi_pend[4]; // 4 * 4 == 16 SGIs a 8 bits

  /// SGI and PPI IRQ array
  Irq_array _local_irq;

  /// SPI IRQ array from distributor
  Irq_array *_spis;

  /// The associated vCPU
  Vmm::Vcpu_ptr _vcpu = Vmm::Vcpu_ptr(nullptr);

  /// The x-CPU notification IRQ
  L4Re::Util::Unique_cap<L4::Irq> _cpu_irq;

  void _set_elsr(l4_uint32_t bits) const
  {
    unsigned id = L4_VCPU_E_GIC_ELSR;
    l4_uint32_t e = l4_vcpu_e_read_32(*_vcpu, id);
    l4_vcpu_e_write_32(*_vcpu, id, e | bits);
  }

  void _clear_elsr(l4_uint32_t bits) const
  {
    unsigned id = L4_VCPU_E_GIC_ELSR;
    l4_uint32_t e = l4_vcpu_e_read_32(*_vcpu, id);
    l4_vcpu_e_write_32(*_vcpu, id, e & ~bits);
  }
};

inline void
Cpu::write_set_sgi_pend(unsigned reg, l4_uint32_t value)
{
  l4_uint32_t o = _sgi_pend[reg];
  l4_uint32_t n = o | value;
  if (o == n)
    return;

  _sgi_pend[reg] = n;

  for (unsigned i = 0; i < 4; ++i)
    {
      if ((o ^ n) & 0xff)
        local_irq(i + (reg * 4)).pending(true);

      o >>= 8;
      n >>= 8;
    }
}

inline void
Cpu::write_clear_sgi_pend(unsigned reg, l4_uint32_t value)
{
  l4_uint32_t o = _sgi_pend[reg];
  l4_uint32_t n = o & ~value;
  if (o == n)
    return;

  _sgi_pend[reg] = n;
  for (unsigned i = 0; i < 4; ++i)
    {
      if ((o ^ n) & 0xff)
        local_irq(i + (reg * 4)).pending(false);

      o >>= 8;
      n >>= 8;
    }
}

template<typename CPU_IF>
inline void
Cpu::handle_eois()
{
  using Lr = typename CPU_IF::Lr;
  using namespace Vmm::Arm;
  Gic_h::Misr misr(l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_MISR));

  if (!misr.eoi())
    return;

  l4_uint32_t eisr = l4_vcpu_e_read_32(*_vcpu, L4_VCPU_E_GIC_EISR);
  if (!eisr)
    return;

  for (unsigned i = 0; i < Num_lrs; ++i, eisr >>= 1)
    {
      if (!(eisr & 1))
        continue;

      Lr lr = CPU_IF::read_lr(_vcpu, i);
      Irq c = irq_from_intid(lr.vid());
      if (!lr.pending())
        {
          c.clear_lr();
          CPU_IF::write_lr(_vcpu, i, Lr(0));
          _set_elsr(1U << i);
        }

      c.eoi(vmm_current_cpu_id, lr.pending());
      c.do_eoi();
    }

  // all EOIs are handled
  l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_GIC_EISR, 0);
  misr.eoi() = 0;
  l4_vcpu_e_write_32(*_vcpu, L4_VCPU_E_GIC_MISR, misr.raw);
}

template<typename CPU_IF>
inline bool
Cpu::add_pending_irq(unsigned lr, Irq const &irq,
                     unsigned irq_id, unsigned src_cpu)
{
  if (!irq.take_on_cpu(vmm_current_cpu_id, 0xff))
    return false;

  using Lr = typename CPU_IF::Lr;
  Lr new_lr(0);
  new_lr.state() = Lr::Pending;
  new_lr.eoi()   = 1; // need an EOI IRQ
  new_lr.vid()   = irq_id;
  new_lr.set_cpuid(src_cpu);
  new_lr.prio()  = irq.prio();
  new_lr.grp1()  = irq.group();

  // uses 0 for "no link register assigned" (see #get_empty_lr())
  irq.set_lr(lr + 1);
  CPU_IF::write_lr(_vcpu, lr, new_lr);
  _clear_elsr(1U << lr);
  return true;
}

template<typename CPU_IF>
inline bool
Cpu::inject(Irq const &irq, unsigned irq_id, unsigned src_cpu)
{
  using Lr = typename CPU_IF::Lr;

  // free LRs if there are inactive LRs
  handle_eois<CPU_IF>();

  // check whether the irq is already in a list register
  unsigned lr_idx = irq.lr();
  if (lr_idx)
    {
      --lr_idx;
      assert(lr_idx < Num_lrs);

      Lr lr = CPU_IF::read_lr(_vcpu, lr_idx);
      if (lr.vid() == irq_id)
        {
          if (!irq.take_on_cpu(vmm_current_cpu_id, 0xff))
            return false;

          lr.pending() = 1;
          CPU_IF::write_lr(_vcpu, lr_idx, lr);
          return true;
        }
      else
        irq.clear_lr();
    }

  // look for an empty list register
  lr_idx = get_empty_lr();
  // currently we use up to 4 (Num_lrs) list registers
  if (!lr_idx)
    {
      // We might try to preempt a lower priority interrupt from the
      // link registers here. But since our main guest does not use
      // priorities we ignore this possibility.
      return false;
    }

  return add_pending_irq<CPU_IF>(lr_idx - 1, irq, irq_id, src_cpu);
}

class Cpu_vector
{
private:
  using Cpu_ptr = cxx::unique_ptr<Cpu>;

  cxx::unique_ptr<Cpu_ptr[]> _cpu;
  unsigned _n = 0;
  unsigned _c = 0;

public:
  explicit Cpu_vector(unsigned capacity)
  : _cpu(cxx::make_unique<Cpu_ptr[]>(capacity)),
    _c(capacity)
  {}

  unsigned capacity() const { return _c; }
  unsigned size() const { return _n; }
  Cpu_ptr const *begin() const { return &_cpu[0]; }
  Cpu_ptr const *end() const { return &_cpu[_n]; }
  Cpu_ptr const &operator [] (unsigned idx) const { return _cpu[idx]; }

  bool set_at(unsigned idx, Cpu_ptr &&cpu)
  {
    if (idx >= capacity())
      return false;

    if ((idx + 1) > _n)
      _n = idx + 1;

    _cpu[idx] = cxx::move(cpu);
    return true;
  }
};


class Dist
: public Dist_if,
  public Ic,
  public Monitor::Gic_cmd_handler<Monitor::Enabled, Dist>
{
  friend Gic_cmd_handler<Monitor::Enabled, Dist>;

protected:
  Dbg gicd_trace;

public:
  using Irq = Cpu::Irq;
  using Const_irq = Cpu::Const_irq;

  enum { Num_local = 32 };

  enum Regs
  {
    CTLR  = 0x000,
    TYPER = 0x004, // RO
    IIDR  = 0x008, // RO
    SGIR  = 0xf00, // WO
  };

  l4_uint32_t ctlr;
  unsigned char tnlines;

  explicit Dist(unsigned tnlines, unsigned max_cpus);

  Irq_array::Irq spi(unsigned spi)
  {
    assert (spi < _spis.size());
    return _spis[spi];
  }

  Irq_array::Const_irq spi(unsigned spi) const
  {
    assert (spi < _spis.size());
    return _spis[spi];
  }

  /// \group Implementation of Ic functions
  /// \{
  void clear(unsigned) override {}

  void bind_eoi_handler(unsigned irq, Eoi_handler *handler) override
  {
    auto pin = spi(irq - Cpu::Num_local);

    if (handler && pin.get_eoi_handler())
      L4Re::chksys(-L4_EEXIST, "Assigning EOI handler to GIC");

    pin.set_eoi(handler);
  }

  Eoi_handler *get_eoi_handler(unsigned irq) const override
  { return spi(irq - Cpu::Num_local).get_eoi_handler(); }

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
  Cpu *add_cpu(Vmm::Vcpu_ptr vcpu, L4::Cap<L4::Thread> thread)
  {
    unsigned cpu = vcpu.get_vcpu_id();


    if (cpu >= _cpu.capacity())
      return nullptr;

    gicd_trace.printf("set CPU interface for CPU %02d (%p) to %p\n",
                      cpu, &_cpu[cpu], *vcpu);
    _cpu.set_at(cpu, cxx::make_unique<Cpu>(vcpu, &_spis, thread));
    if (cpu == 0)
      _prio_mask = ~((1U << (7 - _cpu[cpu]->vtr().pri_bits())) - 1U);
    return _cpu[cpu].get();
  }

  /// write to the GICD_CTLR.
  virtual void write_ctlr(l4_uint32_t val)
  {
    ctlr = val;
  }

  /// read to the GICD_TYPER.
  virtual l4_uint32_t get_typer() const
  {
    return tnlines | ((l4_uint32_t)(_cpu.size() - 1) << 5);
  }

  /// read to the CoreSight IIDRs.
  virtual l4_uint32_t iidr_read(unsigned offset) const = 0;
  /// \}

  /**
   * Show the GIC state, for debugging / tracing.
   */
  void show_state(unsigned current_cpu, char const *file, unsigned line) const
  {
    // early exit if inactive
    if (!gicd_trace.is_active())
      return;

    for (auto const &c: _cpu)
      if (c)
        gicd_trace.printf("%s:%d: Cpu%ld = %p, Gic=%p\n",
                          file, line, (long)(&c - _cpu.begin()),
                          c.get(), *c->vcpu());

    if (current_cpu >= _cpu.capacity())
      return;

    Cpu *c = _cpu[current_cpu].get();
    if (!c)
      return;

    gicd_trace.printf("%s:%d: Irq state for Cpu%d: hcr:%08x, vmcr:%08x\n",
                      file, line, current_cpu,
                      c->hcr().raw,
                      l4_vcpu_e_read_32(*c->vcpu(), L4_VCPU_E_GIC_VMCR));
  }

private:
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

  l4_uint32_t irq_mmio_read(Const_irq const &irq, unsigned rgroup)
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
      case R_target:   return irq.target();
      case R_cfg:      return irq.config();
      case R_grpmod:   return 0;
      case R_nsacr:    return 0;
      default:         assert (false); return 0;
      }
  }

  void irq_mmio_write(Irq const &irq, unsigned rgroup, l4_uint32_t value)
  {
    switch (rgroup)
      {
      case R_group:    irq.group(value);               return;
      case R_isenable: if (value) irq.enable(true);    return;
      case R_icenable: if (value) irq.enable(false);   return;
      case R_ispend:   if (value) irq.pending(true);   return;
      case R_icpend:   if (value) irq.pending(false);  return;
      case R_isactive: if (value) irq.active(true);    return;
      case R_icactive: if (value) irq.active(false);   return;
      case R_prio:     irq.prio(value & _prio_mask);   return;
      case R_target:   irq.target(value);              return;
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

    if (irq_s < Num_local)
      _demux_irq_reg<SHIFT>(_cpu[cpu_id]->local_irqs(), irq_s, nirq, reg, op);
    else if (irq_s - Num_local < _spis.size())
      _demux_irq_reg<SHIFT>(_spis, irq_s - Num_local, nirq, reg, op);
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
    auto rd = [this,res](Const_irq const &irq, unsigned r, l4_uint32_t mask,
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
    auto wr = [this,value](Irq const &irq, unsigned r, l4_uint32_t mask,
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
};

template<typename GIC_IMPL>
void
Cpu::handle_ipis()
{
  if (!GIC_IMPL::sgi_pend_regs())
    return;

  using Cpu_if = typename GIC_IMPL::Cpu_if;

  for (unsigned irq_num = 0; irq_num < 16; ++irq_num)
    {
      using Ma = Vmm::Mem_access;
      unsigned char const cpu_bits
        = Ma::read(_sgi_pend[irq_num / 4], irq_num, Ma::Wd8);

      if (!cpu_bits)
        continue;

      // inject one IPI, if another CPU posted the same IPI we keep it
      // pending
      unsigned src = __builtin_ffs((int)cpu_bits) - 1;
      auto irq = local_irq(irq_num);

      // set irq pending and try to inject
      if (irq.pending(true))
        {
          if (!inject<Cpu_if>(irq, irq_num, src))
            {
              Dbg(Dbg::Cpu, Dbg::Info, "IPI")
                .printf("Cpu%d: Failed to inject irq %d\n",
                        vmm_current_cpu_id, irq_num);
              return;
            }
          clear_sgi(irq_num, src);
        }
      else
        {
          Dbg(Dbg::Cpu, Dbg::Info, "IPI")
            .printf("Cpu%d: Failed to set irq %d to pending,"
                    " current state: %s (%08x)\n",
                    vmm_current_cpu_id, irq_num,
                    irq.pending() ? "pending" : "not pending", irq.state());
        }
    }
}

}

