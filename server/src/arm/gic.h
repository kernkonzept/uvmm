/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
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
#include "mmio_device.h"
#include "irq.h"

extern __thread unsigned vmm_current_cpu_id;

namespace Gic {

class Irq_array
{
private:
  struct Pending
  {
  private:
    // collects bits used to implement various distributor registers
    l4_uint32_t _state;

  public:
    CXX_BITFIELD_MEMBER_RO( 0,  0, pending,     _state); // GICD_I[SC]PENDRn
    CXX_BITFIELD_MEMBER_RO( 1,  1, active,      _state); // GICD_I[SC]ACTIVERn
    CXX_BITFIELD_MEMBER_RO( 3,  3, enabled,     _state); // GICD_I[SC]ENABLERn
    CXX_BITFIELD_MEMBER_RO( 4,  7, cpu,         _state);
    CXX_BITFIELD_MEMBER_RO( 8, 11, src,         _state);

    CXX_BITFIELD_MEMBER_RO(15, 22, target,      _state); // GICD_ITARGETSRn
    CXX_BITFIELD_MEMBER_RO(23, 27, prio,        _state); // GICD_IPRIORITYRn
    CXX_BITFIELD_MEMBER_RO(28, 29, config,      _state); // GICD_ICFGRn
    CXX_BITFIELD_MEMBER_RO(30, 30, group,       _state); // GICD_IGROUPRn

  private:

    enum
    {
      Pending_and_enabled = pending_bfm_t::Mask | enabled_bfm_t::Mask
    };

    static l4_uint32_t is_pending_and_enabled(l4_uint32_t state)
    { return (state & Pending_and_enabled) == Pending_and_enabled; }

    static l4_uint32_t is_pending_or_enabled(l4_uint32_t state)
    { return state & Pending_and_enabled; }

    Pending(Pending const &) = delete;
    Pending operator = (Pending const &) = delete;

    /**
     * Set the enabled bit and conditionally the new_pending bit if
     * the irq was already pending.
     * \return true if we made a new IRQ pending.
     */
    bool set_pe(unsigned char set);

    /**
     * Clear the enabled and the new_pending flag
     * \return true if the IRQ was disabled and previously new_pending.
     */
    bool clear_pe(unsigned char clear);

  public:
    Pending() : _state(0) {}
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

    bool consume(unsigned char cpu);
    bool eoi(unsigned char cpu, bool pending);
    void kick_from_cpu(unsigned char cpu);
    bool take_on_cpu(unsigned char cpu, unsigned char min_prio,
                     bool make_pending);
    bool prio(unsigned char p);
    bool active(bool a);
    bool group(bool grp1);
    bool config(unsigned cfg);
    bool target(unsigned char tgt);

    static void show_header(FILE *f);
    void show(FILE *f, int irq) const;
  };

  struct Context
  {
    cxx::Ref_ptr<Irq_source> eoi;
    /*
     * Keeps track of the used lr, uses 0 for "no link register
     * assigned" (see #get_empty_lr())
     */
    unsigned char lr;
    Context() : eoi(0), lr(0) {};
  };

  cxx::unique_ptr<Pending[]> _pending;
  cxx::unique_ptr<Context[]> _irq;

public:
  class Const_irq
  {
  public:
    l4_uint32_t state() const { return _p->state(); }
    bool enabled() const { return _p->enabled(); }
    bool pending() const { return _p->pending(); }
    bool active() const { return _p->active(); }
    bool group() const { return _p->group(); }
    unsigned char config() const { return _p->config(); }
    unsigned char prio() const { return _p->prio(); }
    unsigned char target() const { return _p->target(); }

    void do_eoi() const { if (_c->eoi) _c->eoi->eoi(); }
    cxx::Ref_ptr<Irq_source> get_source() const { return _c->eoi; }

    unsigned cpu() const { return _p->cpu(); }
    unsigned lr() const { return _c->lr; }

    Const_irq &operator ++ () { ++_c; ++_p; return *this; }

    bool operator == (Const_irq const &r) const { return _p == r._p; }
    bool operator != (Const_irq const &r) const { return _p != r._p; }

    static void show_header(FILE *f)
    { Pending::show_header(f); }
    void show(FILE *f, int irq)
    { _p->show(f, irq); }
  protected:
    friend class Irq_array;
    Const_irq(Pending *p, Context *c) : _p(p), _c(c) {}

    Pending *_p;
    Context *_c;
  };

  class Irq : public Const_irq
  {
  public:
    void set_eoi(cxx::Ref_ptr<Irq_source> const &eoi) { _c->eoi = eoi; }
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

    bool consume(unsigned char cpu) const
    {
      return _p->consume(cpu);
    }

    bool take_on_cpu(unsigned char cpu, unsigned char min_prio,
                     bool make_pending) const
    {
      return _p->take_on_cpu(cpu, min_prio, make_pending);
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
    Irq(Pending *p, Context *c) : Const_irq(p, c) {}
  };


  explicit Irq_array(unsigned irqs)
  {
    _pending = cxx::unique_ptr<Pending[]>(new Pending[irqs]);
    _irq     = cxx::unique_ptr<Context[]>(new Context[irqs]);
  }

  Irq operator [] (unsigned i)
  { return Irq(_pending.get() + i, _irq.get() + i); }

  Const_irq operator [] (unsigned i) const
  { return Const_irq(_pending.get() + i, _irq.get() + i); }

  int find_pending_irq(unsigned char target_mask, unsigned char min_prio,
                       unsigned begin, unsigned end)
  {
    int hp_irq = -1;
    unsigned char hprio = min_prio;

    for (Pending *p = _pending.get() + begin; p != _pending.get() + end; ++p)
      {
        if (!p->enabled() || !p->pending())
          continue;

        if (!(p->target() & target_mask))
          continue;

        if (p->cpu())
          continue;

        if (!(p->prio() < hprio))
          continue;

        // found a potential victim
        hp_irq = p - _pending.get();
        hprio = p->prio();
      }

    return hp_irq;
  }

};

//////////////////////////////
// Irq_array::Pending
//////////////////////////////

/**
 * Set the enabled bit and conditionally the new_pending bit if
 * the irq was already pending.
 * \return true if we made a new IRQ pending.
 */
inline bool
Irq_array::Pending::set_pe(unsigned char set)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  do
    {
      if (old & set)
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, old | set, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return is_pending_or_enabled(old);
}

/**
 * Clear the enabled and the new_pending flag
 * \return true if the IRQ was disabled and previously new_pending.
 */
inline bool
Irq_array::Pending::clear_pe(unsigned char clear)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  do
    {
      if (!(old & clear))
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, old & ~clear, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return is_pending_and_enabled(old);
}

inline bool
Irq_array::Pending::consume(unsigned char cpu)
{
  assert (cpu < 8);
  cpu += target_bfm_t::Lsb;
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  do
    {
      if (!(old & (1UL << cpu)))
        return false; // not for our CPU

      if (prio_bfm_t::get(old) >= 0x1f)
        return false; // never used because prio >= idle prio
    }
  while (!__atomic_compare_exchange_n(&_state, &old,
                                      old & ~pending_bfm_t::Mask,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return is_pending_and_enabled(old);
}

inline bool
Irq_array::Pending::eoi(unsigned char cpu, bool pending)
{
  assert (cpu < 8);
  assert (this->cpu() == cpu + 1);

  // ok, the assumption is that this IRQ is on CPU cpu
  // and we are currently running on CPU cpu, so this
  // this->cpu() cannot change here
  l4_uint32_t mask = pending ? ~active_bfm_t::Mask
                             : ~(cpu_bfm_t::Mask | active_bfm_t::Mask);
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  while (!__atomic_compare_exchange_n(&_state, &old,
                                      old & mask,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    ;
  return false;
}

inline void
Irq_array::Pending::kick_from_cpu(unsigned char cpu)
{
  assert (cpu < 8);
  assert (this->cpu() == cpu + 1);
  // ok, the assumption is that this IRQ is on CPU cpu
  // and we are currently running on CPU cpu, so this
  // this->cpu() cannot change here
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  while (!__atomic_compare_exchange_n(&_state, &old,
                                      (old & ~cpu_bfm_t::Mask) | pending_bfm_t::Mask,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    ;
}

inline bool
log_failure(l4_uint32_t state, unsigned char cpu, unsigned char min_prio,
            bool make_pending, char const *txt)
{
  Dbg(Dbg::Irq, Dbg::Trace, "Gic")
    .printf("Cpu%d: state: %08x - take_on_cpu(%d, %d, %s) -> %s\n",
            vmm_current_cpu_id, state, cpu,
            min_prio, make_pending ? "true" : "false", txt);
  return false;
}

inline bool
Irq_array::Pending::take_on_cpu(unsigned char cpu, unsigned char min_prio,
                                bool make_pending)
{
  assert (cpu < 8);
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;
  do
    {
      l4_uint32_t current = cpu_bfm_t::get(old);
      if (current != 0)
        {
          if (current != cpu + 1U)
            return log_failure(old, cpu, min_prio, make_pending,
                               "already on a different CPU");
          nv = old;
        }
      else
        nv = old | cpu_bfm_t::val_dirty(cpu + 1);

      if (!(old & (1UL << (cpu + target_bfm_t::Lsb))))
        return log_failure(old, cpu, min_prio, make_pending,
                           "not for us, skip it");

      if (!is_pending_and_enabled(old))
        return log_failure(old, cpu, min_prio, make_pending,
                           "not pending, so no need to take");

      if (prio_bfm_t::get(old) >= min_prio)
        return log_failure(old, cpu, min_prio, make_pending, "priority");

      if (make_pending)
        nv = (nv & ~pending_bfm_t::Mask) | active_bfm_t::Mask;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return true;
}

inline bool
Irq_array::Pending::prio(unsigned char p)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;
  do
    {
      nv = prio_bfm_t::set_dirty(old, p);
      if (old == nv)
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return true;
}

inline bool
Irq_array::Pending::active(bool a)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;
  do
    {
      nv = active_bfm_t::set_dirty(old, a);
      if (nv == old)
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return true;
}

inline bool
Irq_array::Pending::group(bool grp1)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;
  do
    {
      nv = group_bfm_t::set_dirty(old, grp1);
      if (nv == old)
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return true;
}

inline bool
Irq_array::Pending::config(unsigned cfg)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;
  do
    {
      nv = config_bfm_t::set_dirty(old, cfg);
      if (old == nv)
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return true;
}

inline bool
Irq_array::Pending::target(unsigned char tgt)
{
  l4_uint32_t old = __atomic_load_n(&_state, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;
  do
    {
      nv = target_bfm_t::set_dirty(old, tgt);
      if (old == nv)
        return false;
    }
  while (!__atomic_compare_exchange_n(&_state, &old, nv,
                                      true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
  return true;
}


///////////////////////////////////////////////////////////////////////////////
// GIC CPU interface
class Cpu
{
public:
  enum { Num_local = 32 };
  enum { Num_lrs = 4 };

  static_assert(Num_lrs <= 32, "Can only handle up to 32 list registers.");

  Cpu() : _local_irq(Num_local)
  {
    memset(&_sgi_pend, 0, sizeof(_sgi_pend));
    _cpu_irq = L4Re::chkcap(L4Re::Util::make_unique_cap<L4::Irq>(),
                            "allocate vcpu notification interrupt");
    L4Re::chksys(L4Re::Env::env()->factory()->create(_cpu_irq.get()),
                 "create vcpu notification interrupt");
  }

  void setup(unsigned cpuid, Irq_array *spis);

  void attach_cpu_thread(L4::Cap<L4::Thread> thread)
  { L4Re::chksys(_cpu_irq->bind_thread(thread, 0)); }

  Irq_array::Irq local_irq(unsigned irqn) { return _local_irq[irqn]; }

  /*
   * Get empty list register
   *
   * \return Returns 0 if no empty list register is available, (lr_idx
   *         + 1) otherwise
   */
  unsigned get_empty_lr() const
  { return __builtin_ffs(_vgic->elsr[0]); }

  bool pending_irqs() const { return _vgic->elsr[0] != (1ULL << Num_lrs) - 1; }

  Irq_array::Irq irq(unsigned irqn);
  Irq_array::Const_irq irq(unsigned irqn) const;

  Vmm::Arm::State::Gic *vgic() const { return _vgic; }
  void vgic(Vmm::Arm::State::Gic *gic) { _vgic = gic; }

  void ipi(unsigned irq);
  void notify()
  { _cpu_irq->trigger(); }

  l4_uint32_t read_sgi_pend(unsigned reg)
  { return _sgi_pend[reg]; }

  void write_set_sgi_pend(unsigned reg, l4_uint32_t value);
  void write_clear_sgi_pend(unsigned reg, l4_uint32_t value);
  void handle_eois();
  bool add_pending_irq(unsigned lr, Irq_array::Irq const &irq, unsigned irq_id,
                       unsigned src_cpu = 0);

  unsigned find_pending_irq(unsigned char target_mask, unsigned char min_prio)
  { return _local_irq.find_pending_irq(target_mask, min_prio, 0, Num_local); }

  bool inject(Irq_array::Irq const &irq, unsigned irq_id, unsigned src_cpu = 0);
  void handle_maintenance_irq(unsigned current_cpu);

  void set_work_pending()
  { cxx::write_now(&_pending_work, true); }

  bool is_work_pending() const
  { return cxx::access_once(&_pending_work); }

  void handle_ipis();
  bool set_sgi(unsigned irq);
  void clear_sgi(unsigned irq, unsigned src);
  void dump_sgis() const;

  void show(FILE *f, unsigned cpu);

 private:
  l4_uint32_t _sgi_pend[4]; // 4 * 4 == 16 SGIs a 8 bits

  Irq_array _local_irq;
  Irq_array *_spis;
  Vmm::Arm::State::Gic *_vgic = 0;
  L4Re::Util::Unique_cap<L4::Irq> _cpu_irq;
  bool _pending_work;
};


inline void
Cpu::setup(unsigned cpuid, Irq_array *spis)
{
  if (0)
    printf("SETUP GIC CPUIF[%02d]: @%p\n", cpuid, this);
  assert (cpuid < 8);
  _spis = spis;
  for (Irq_array::Irq i = _local_irq[0]; i != _local_irq[Num_local]; ++i)
    i.target(1 << cpuid);
}

inline Irq_array::Irq
Cpu::irq(unsigned irqn)
{
  if (irqn < Num_local)
    return _local_irq[irqn];
  else
    return (*_spis)[irqn - Num_local];
}

inline Irq_array::Const_irq
Cpu::irq(unsigned irqn) const
{
  if (irqn < Num_local)
    return _local_irq[irqn];
  else
    return (*_spis)[irqn - Num_local];
}

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

inline void
Cpu::handle_eois()
{
  if (!_vgic->misr.eoi())
    return;

  unsigned ridx = 0;
  // currently we use up to 4 (Num_lrs) list registers
  l4_uint32_t eisr = _vgic->eisr[ridx];
  if (!eisr)
    return;

  for (unsigned i = 0; i < Num_lrs; ++i, eisr >>= 1)
    {
      if (!(eisr & 1))
        continue;

      Irq_array::Irq c = irq(_vgic->lr[i].vid());
      bool pending = _vgic->lr[i].pending();
      if (!pending)
        {
          c.clear_lr();
          _vgic->lr[i] = Vmm::Arm::Gic_h::Lr(0);
          _vgic->elsr[ridx] |= (1 << i); // maintain our SW state
        }
      c.do_eoi();
      c.eoi(vmm_current_cpu_id, pending);
    }

  // all EOIs are handled
  _vgic->eisr[ridx] = 0;
  _vgic->misr.eoi() = 0;
}

inline bool
Cpu::add_pending_irq(unsigned lr, Irq_array::Irq const &irq,
                     unsigned irq_id, unsigned src_cpu)
{
  if (!irq.take_on_cpu(vmm_current_cpu_id, 0xff, true))
    return false;

  using Vmm::Arm::Gic_h::Lr;
  Lr new_lr(0);
  new_lr.state() = Lr::Pending;
  new_lr.eoi()   = 1; // need an EOI IRQ
  new_lr.vid()   = irq_id;
  new_lr.cpuid() = src_cpu;
  new_lr.prio()  = irq.prio();
  new_lr.grp1()  = irq.group();

  // uses 0 for "no link register assigned" (see #get_empty_lr())
  irq.set_lr(lr + 1);

  _vgic->lr[lr] = new_lr;
  _vgic->elsr[0] &= ~(1UL << lr);
  return true;
}


inline bool
Cpu::inject(Irq_array::Irq const &irq, unsigned irq_id, unsigned src_cpu)
{
  using Vmm::Arm::Gic_h::Lr;

  handle_eois();

  // check whether the irq is already in a list register
  unsigned lr_idx = irq.lr();
  if (lr_idx)
    {
      --lr_idx;
      assert(lr_idx < Num_lrs);

      if (_vgic->lr[lr_idx].vid() == irq_id)
        {
          if (!irq.take_on_cpu(vmm_current_cpu_id, 0xff, true))
            return false;

          _vgic->lr[lr_idx].pending() = 1;
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
      Lr lowest(0);
      if (0)
        {
          // search the LR with the lowest priority pending IRQ
          unsigned min_prio = 0;
          for (unsigned i = 0; i < Num_lrs; ++i)
            {
              Lr l = _vgic->lr[i];
              if (   l.state() == Lr::Pending
                  && l.prio() > min_prio
                  && l.prio() > irq.prio())
                {
                  lowest = l;
                  lr_idx = i + 1;
                  min_prio = l.prio();
                }
            }
        }

      if (!lr_idx)
        {
          if (0)
            {
              printf("VGIC full while trying to inject irq 0x%x : ", irq_id);
              for (unsigned i = 0; i < Num_lrs; ++i)
                printf("%d: %x ", i, _vgic->lr[i].raw);
              printf("\n");
            }

          return false;
        }

      if (0)
        this->irq(lowest.vid()).kick_from_cpu(vmm_current_cpu_id);
    }

  return add_pending_irq(lr_idx - 1, irq, irq_id, src_cpu);
}

inline void
Cpu::handle_maintenance_irq(unsigned /*current_cpu*/)
{
  handle_eois();
}



class Dist : public Vmm::Mmio_device_t<Dist>, public Ic
{
private:
  Dbg gicd_info;

public:
  enum Regs
  {
    CTLR  = 0x000,
    TYPER = 0x004, // RO
    IIDR  = 0x008, // RO
    SGIR  = 0xf00, // WO
  };

  enum Blocks
  {
    RB_enable = 0,
    RB_pending,
    RB_active,
  };

  l4_uint32_t ctlr;
  unsigned char tnlines;
  unsigned char cpus;

  struct Reg_group_info
  {
    unsigned short base;
    unsigned char shift;
    unsigned char mask;
  };

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
    R_cfg
  };

  enum Irq_types
  {
    Irq_ppi_base = 16,
    Irq_ppi_max = 16,
    Irq_spi_base = Cpu::Num_local,
  };

  enum Dts_interrupt_cells
  {
    Irq_cell_type = 0,
    Irq_cell_number = 1,
    Irq_cell_flags = 2,
    Irq_cells = 3
  };

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


  static Reg_group_info const reg_group[10];

  Irq_array::Irq spi(unsigned spi)
  {
    assert (spi < tnlines * 32);
    return _spis[spi];
  }

  Irq_array::Const_irq spi(unsigned spi) const
  {
    assert (spi < tnlines * 32);
    return _spis[spi];
  }

  Irq_array::Irq ppi(unsigned ppi, unsigned cpu)
  {
    assert(ppi < Cpu::Num_local);
    return _cpu[cpu].irq(ppi);
  }

  void set(unsigned irq) override
  {
    if (irq < Cpu::Num_local)
      inject_local(irq, vmm_current_cpu_id);
    else
      inject_irq(this->spi(irq - Cpu::Num_local), irq, vmm_current_cpu_id); // SPI
  }

  void clear(unsigned) override {}

  void bind_irq_source(unsigned irq, cxx::Ref_ptr<Irq_source> const &src) override
  {
    auto pin = spi(irq - Cpu::Num_local);
    assert (!pin.get_source());
    pin.set_eoi(src);
  }

  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned irq) const override
  { return spi(irq - Cpu::Num_local).get_source(); }

  int dt_get_num_interrupts(Vdev::Dt_node const &node) override
  {
    int size;
    auto prop = node.get_prop<fdt32_t>("interrupts", &size);

    return prop ? (size / Irq_cells) : 0;
  }

  unsigned dt_get_interrupt(Vdev::Dt_node const &node, int irq) override
  {
    auto *prop = node.check_prop<fdt32_t[Irq_cells]>("interrupts", irq + 1);

    int irqnr = fdt32_to_cpu(prop[irq][Irq_cell_number]);

    if (fdt32_to_cpu(prop[irq][Irq_cell_type]) == 0)
      return irqnr + Irq_spi_base;

    if (irqnr >= Irq_ppi_max)
      L4Re::chksys(-L4_EINVAL, "Only 16 PPI interrupts allowed");

    return irqnr + Irq_ppi_base;
  }

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override
  {}

  Dist(unsigned tnlines, unsigned char cpus);

  l4_uint32_t read(unsigned reg, char size, unsigned cpu_id);
  void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id);

  l4_uint32_t irq_mmio_read(Irq_array::Const_irq const &irq, unsigned rgroup)
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
      case R_prio:     return irq.prio() << 3;
      case R_target:   return irq.target();
      case R_cfg:      return irq.config();
      default:         assert (false); return 0;
      }
  }

  void irq_mmio_write(Irq_array::Irq const &irq, unsigned irq_id,
                      unsigned rgroup, l4_uint32_t value)
  {
    (void)irq_id;
    switch (rgroup)
      {
      case R_group:    irq.group(value);               return;
      case R_isenable: if (value) irq.enable(true);    return;
      case R_icenable: if (value) irq.enable(false);   return;
      case R_ispend:   if (value) irq.pending(true);   return;
      case R_icpend:   if (value) irq.pending(false);  return;
      case R_isactive: if (value) irq.active(true);    return;
      case R_icactive: if (value) irq.active(false);   return;
      case R_prio:     irq.prio((value >> 3) & 0x1f);  return;
      case R_target:   irq.target(value);              return;
      case R_cfg:      irq.config(value);              return;
      default:         assert (false);                 return;
      }
  }

  void notify_cpus(unsigned mask) const;

  void inject_irq(Irq_array::Irq const &irq, unsigned id, unsigned current_cpu)
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
            if (_cpu[current_cpu].inject(irq, id))
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

  void
  inject_local(unsigned id, unsigned current_cpu)
  {
    Cpu *cpu = &_cpu[current_cpu];
    Irq_array::Irq const &irq = cpu->irq(id);
    if (irq.pending(true))
      {
        // need to take some action to pass IRQ to a CPU
        unsigned char current = 1 << current_cpu;
        unsigned char active_mask = irq.group()
                                  ? cxx::access_once(&_active_grp1_cpus)
                                  : cxx::access_once(&_active_grp0_cpus);
        if ((current & active_mask) && cpu->inject(irq, id))
          return;
      }
  }

  void set_cpu(unsigned cpu, Vmm::Arm::State::Gic *iface,
               L4::Cap<L4::Thread> thread)
  {
    if (cpu >= cpus)
      return;

    gicd_info.printf("set CPU interface for CPU %02d (%p) to %p\n",
                     cpu, &_cpu[cpu], iface);
    _cpu[cpu].vgic(iface);
    _cpu[cpu].attach_cpu_thread(thread);
  }

  static void init_vgic(Vmm::Arm::State::Gic *iface)
  {
    using namespace Vmm::Arm;
    iface->vmcr = Gic_h::Vmcr(0);
    iface->vmcr.pri_mask() = 0x1f; // lowest possible prio
    iface->vmcr.bp() = 2; // lowest possible value for 32 prios
    iface->vmcr.abp() = 2;
    // enable the interface and some maintenance settings
    iface->hcr = Gic_h::Hcr(0);
    iface->hcr.en() = 1;
    iface->hcr.vgrp0_eie() = 1;
    iface->hcr.vgrp1_eie() = 1;
  }

  bool schedule_irqs(unsigned current_cpu)
  {
    assert (current_cpu < cpus);
    Cpu *c = &_cpu[current_cpu];

    c->handle_eois();
    c->handle_ipis();

    int pmask = c->vgic()->vmcr.pri_mask() << 3;

    for (;;)
      {
        unsigned empty_lr = c->get_empty_lr();

        if (!empty_lr)
          return true;

        int irq_id = c->find_pending_irq(1 << current_cpu, pmask);
        if (irq_id < 0)
          {
            irq_id = _spis.find_pending_irq(1 << current_cpu,
                                            pmask, 0, tnlines * 32);
            if (irq_id < 0)
              return c->pending_irqs();

            irq_id += Cpu::Num_local;
          }
        if (0)
          gicd_info.printf("Try to inject: irq=%d on cpu=%d... ",
                           irq_id, current_cpu);
        bool ok = c->add_pending_irq(empty_lr - 1, c->irq(irq_id), irq_id);
        if (0)
          gicd_info.printf("%s\n", ok ? "OK" : "FAILED");
      }
  }

  void show_state(unsigned current_cpu, char const *file, unsigned line) const
  {
    assert (current_cpu < cpus);
    for (int i = 0; i < cpus; ++i)
       gicd_info.printf("%s:%d: Cpu%d = %p, Gic=%p\n",
                        file, line, i, &_cpu[i], _cpu[i].vgic());
    Cpu &c = _cpu[current_cpu];
    if (c.vgic())
      {
        gicd_info.printf("%s:%d: Irq state for Cpu%d: hcr:%08x, vmcr:%08x\n",
                         file, line, current_cpu,
                         c.vgic()->hcr.raw, c.vgic()->vmcr.raw);
      }
  }

  void handle_maintenance_irq(unsigned current_cpu)
  {
    assert (current_cpu < cpus);
    Cpu *c = &_cpu[current_cpu];
    Vmm::Arm::Gic_h::Misr misr = c->vgic()->misr;
    Vmm::Arm::Gic_h::Hcr &hcr = c->vgic()->hcr;
    if (misr.grp0_e())
      {
        __atomic_or_fetch(&_active_grp0_cpus, (1UL << current_cpu), __ATOMIC_SEQ_CST);
        hcr.vgrp0_eie() = 0;
        hcr.vgrp0_die() = 1;
      }

    if (misr.grp0_d())
      {
        __atomic_and_fetch(&_active_grp0_cpus, ~(1UL << current_cpu), __ATOMIC_SEQ_CST);
        hcr.vgrp0_eie() = 1;
        hcr.vgrp0_die() = 0;
      }

    if (misr.grp1_e())
      {
        __atomic_or_fetch(&_active_grp1_cpus, (1UL << current_cpu), __ATOMIC_SEQ_CST);
        hcr.vgrp1_eie() = 0;
        hcr.vgrp1_die() = 1;
      }

    if (misr.grp1_d())
      {
        __atomic_and_fetch(&_active_grp1_cpus, ~(1UL << current_cpu), __ATOMIC_SEQ_CST);
        hcr.vgrp1_eie() = 1;
        hcr.vgrp1_die() = 0;
      }

    c->handle_maintenance_irq(current_cpu);
  }

  void show(FILE *f) const;
private:
  void sgir_write(l4_uint32_t value);
  unsigned char _active_grp0_cpus;
  unsigned char _active_grp1_cpus;
  cxx::unique_ptr<Cpu[]> _cpu;
  Irq_array _spis;
};

}
