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
#include "arch_mmio_device.h"
#include "irq.h"

extern __thread unsigned vmm_current_cpu_id;

inline
unsigned char
atomic_or(unsigned char *l, unsigned char bits)
{
  unsigned char old;
  unsigned long tmp, ret;

  asm volatile (
      "1:                                 \n"
      "ldrexb  %[old], [%[mem]]           \n"
      "orr     %[v], %[old], %[orval]     \n"
      "strexb  %[ret], %[v], [%[mem]]     \n"
      "teq     %[ret], #0                 \n"
      "bne     1b                         \n"
      : [old] "=&r" (old), [v] "=&r" (tmp), [ret] "=&r" (ret), "+Q" (*l)
      : [mem] "r" (l), [orval] "Ir" (bits)
      : "cc");
  return old;
}

inline
unsigned char
atomic_and(unsigned char *l, unsigned char bits)
{
  unsigned char old;
  unsigned long tmp, ret;

  asm volatile (
      "1:                                 \n"
      "ldrexb  %[old], [%[mem]]           \n"
      "and     %[v], %[old], %[andval]    \n"
      "strexb  %[ret], %[v], [%[mem]]     \n"
      "teq     %[ret], #0                 \n"
      "bne     1b                         \n"
      : [old] "=&r" (old), [v] "=&r" (tmp), [ret] "=&r" (ret), "+Q" (*l)
      : [mem] "r" (l), [andval] "Ir" (bits)
      : "cc");
  return old;
}

inline bool
mp_cas(unsigned char *m, unsigned char o, unsigned char n)
{
  unsigned long tmp, res;

  asm volatile
    ("mov      %[res], #1           \n"
     "1:                            \n"
     "ldrb     %[tmp], [%[m]]       \n"
     "teq      %[tmp], %[o]         \n"
     "bne      2f                   \n"
     "ldrexb   %[tmp], [%[m]]       \n"
     "teq      %[tmp], %[o]         \n"
     "strexbeq %[res], %[n], [%[m]] \n"
     "teq      %[res], #1           \n"
     "beq      1b                   \n"
     "2:                            \n"
     : [tmp] "=&r" (tmp), [res] "=&r" (res), "+m" (*m)
     : [n] "r" (n), [m] "r" (m), [o] "r" (o)
     : "cc");

  // res == 0 is ok
  // res == 1 is failed

  return !res;
}

inline bool
mp_cas(l4_uint32_t *m, l4_uint32_t o, l4_uint32_t n)
{
  l4_uint32_t tmp, res;

  asm volatile
    ("mov      %[res], #1           \n"
     "1:                            \n"
     "ldr      %[tmp], [%[m]]       \n"
     "teq      %[tmp], %[o]         \n"
     "bne      2f                   \n"
     "ldrex    %[tmp], [%[m]]       \n"
     "teq      %[tmp], %[o]         \n"
     "strexeq  %[res], %[n], [%[m]] \n"
     "teq      %[res], #1           \n"
     "beq      1b                   \n"
     "2:                            \n"
     : [tmp] "=&r" (tmp), [res] "=&r" (res), "+m" (*m)
     : [n] "r" (n), [m] "r" (m), [o] "r" (o)
     : "cc");

  // res == 0 is ok
  // res == 1 is failed

  return !res;
}

inline void mp_wmb()
{ __asm__ __volatile__ ("" : : : "memory"); }


namespace Gic {

class Irq_array
{
private:
  struct Pending
  {
  private:
    l4_uint32_t _state;

  public:
    CXX_BITFIELD_MEMBER_RO( 0,  0, pending,     _state);
    CXX_BITFIELD_MEMBER_RO( 1,  1, active,      _state);
    CXX_BITFIELD_MEMBER_RO( 3,  3, enabled,     _state);
    CXX_BITFIELD_MEMBER_RO( 4,  7, cpu,         _state);

    CXX_BITFIELD_MEMBER_RO( 8, 15, target,      _state);
    CXX_BITFIELD_MEMBER_RO(23, 27, prio,        _state);
    CXX_BITFIELD_MEMBER_RO(28, 29, config,      _state);
    CXX_BITFIELD_MEMBER_RO(30, 30, group,       _state);

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

    bool enable()
    { return set_pe(enabled_bfm_t::Mask); }

    bool disable()
    { return clear_pe(enabled_bfm_t::Mask); }

    bool set_pending()
    { return set_pe(pending_bfm_t::Mask); }

    bool clear_pending()
    { return clear_pe(pending_bfm_t::Mask); }

    bool consume(unsigned char cpu);
    bool eoi(unsigned char cpu);
    void kick_from_cpu(unsigned char cpu);
    bool take_on_cpu(unsigned char cpu, unsigned char min_prio,
                     bool make_pending);
    bool prio(unsigned char p);
    bool active(bool a);
    bool group(bool grp1);
    bool config(unsigned cfg);
    bool target(unsigned char tgt);
  };

  struct Context
  {
    cxx::Ref_ptr<Irq_source> eoi;
    unsigned char lr;
  };

  cxx::unique_ptr<Pending[]> _pending;
  cxx::unique_ptr<Context[]> _irq;

public:
  class Const_irq
  {
  public:
    bool enabled() const { return _p->enabled(); }
    bool pending() const { return _p->pending(); }
    bool active() const { return _p->active(); }
    bool group() const { return _p->group(); }
    unsigned char config() const { return _p->config(); }
    unsigned char prio() const { return _p->prio(); }
    unsigned char target() const { return _p->target(); }

    void do_eoi() const { if (_c->eoi) _c->eoi->eoi(); }

    unsigned cpu() const { return _p->cpu(); }
    unsigned lr() const { return _c->lr; }

    Const_irq &operator ++ () { ++_c; ++_p; return *this; }

    bool operator == (Const_irq const &r) const { return _p == r._p; }
    bool operator != (Const_irq const &r) const { return _p != r._p; }

  protected:
    friend class Irq_array;
    Const_irq(Pending *p, Context *c) : _p(p), _c(c) {}

    Pending *_p;
    Context *_c;
  };

  class Irq : public Const_irq
  {
  public:
    void set_eoi(cxx::Ref_ptr<Irq_source> eoi) { _c->eoi = eoi; }
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
    bool eoi(unsigned cpu) const { return _p->eoi(cpu); }
    using Const_irq::active;
    void active(bool act) const { _p->active(act); }
    using Const_irq::group;
    void group(bool grp1) const { _p->group(grp1); }
    using Const_irq::config;
    void config(unsigned char cfg) const { _p->config(cfg); }

    void set_lr(unsigned idx) const { _c->lr = idx; }

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

        if (!p->target() & target_mask)
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
  l4_uint32_t old, nv;
  do
    {
      nv = old = cxx::access_once(&_state);
      if (old & set)
        return false;
    }
  while (!mp_cas(&_state, old, nv | set));
  return is_pending_or_enabled(old);
}

/**
 * Clear the enabled and the new_pending flag
 * \return true if the IRQ was disabled and previously new_pending.
 */
inline bool
Irq_array::Pending::clear_pe(unsigned char clear)
{
  l4_uint32_t old, nv;
  do
    {
      nv = old = cxx::access_once(&_state);
      if (!(old & clear))
        return false;
    }
  while (!mp_cas(&_state, old, nv & ~clear));
  return is_pending_and_enabled(old);
}

inline bool
Irq_array::Pending::consume(unsigned char cpu)
{
  assert (cpu < 8);
  cpu += target_bfm_t::Lsb;
  l4_uint32_t old;
  do
    {
      old = cxx::access_once(&_state);

      if (!(old & (1UL << cpu)))
        return false; // not for our CPU

      if (prio_bfm_t::get(old) >= 0x1f)
        return false; // never used because prio >= ilde prio
    }
  while (!mp_cas(&_state, old, old & ~pending_bfm_t::Mask));
  return is_pending_and_enabled(old);
}

inline bool
Irq_array::Pending::eoi(unsigned char cpu)
{
  assert (cpu < 8);
  assert (this->cpu() == cpu + 1);

  // ok, the assumption is that this IRQ is on CPU cpu
  // and we are currently running on CPU cpu, so this
  // this->cpu() cannot change here
  l4_uint32_t old;
  do
    old = cxx::access_once(&_state);
  while (!mp_cas(&_state, old, old & ~(cpu_bfm_t::Mask | active_bfm_t::Mask)));
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
  l4_uint32_t old;
  do
    old = cxx::access_once(&_state);
  while (!mp_cas(&_state, old, (old & ~cpu_bfm_t::Mask) | pending_bfm_t::Mask));
}


inline bool
Irq_array::Pending::take_on_cpu(unsigned char cpu, unsigned char min_prio,
                                bool make_pending)
{
  assert (cpu < 8);
  l4_uint32_t old, nv;
  do
    {
      old = cxx::access_once(&_state);

      if (cpu_bfm_t::get(old) != 0)
        return false; // already on a different CPU

      if (!(old & (1UL << (cpu + target_bfm_t::Lsb))))
        return false; // not for us, skip it

      if (!is_pending_and_enabled(old))
        return false; // not pending, so no need to take

      if (prio_bfm_t::get(old) >= min_prio)
        return false; // priority

      nv = old | cpu_bfm_t::val_dirty(cpu + 1);
      if (make_pending)
        nv = (nv & ~pending_bfm_t::Mask) | active_bfm_t::Mask;
    }
  while (!mp_cas(&_state, old, nv));
  return true;
}

inline bool
Irq_array::Pending::prio(unsigned char p)
{
  l4_uint32_t old, nv;
  do
    {
      old = cxx::access_once(&_state);
      nv = prio_bfm_t::set_dirty(old, p);
      if (old == nv)
        return false;
    }
  while (!mp_cas(&_state, old, nv));
  return true;
}

inline bool
Irq_array::Pending::active(bool a)
{
  l4_uint32_t old, nv;
  do
    {
      old = cxx::access_once(&_state);
      nv = active_bfm_t::set_dirty(old, a);
      if (nv == old)
        return false;
    }
  while (!mp_cas(&_state, old, nv));
  return true;
}

inline bool
Irq_array::Pending::group(bool grp1)
{
  l4_uint32_t old, nv;
  do
    {
      old = cxx::access_once(&_state);
      nv = group_bfm_t::set_dirty(old, grp1);
      if (nv == old)
        return false;
    }
  while (!mp_cas(&_state, old, nv));
  return true;
}

inline bool
Irq_array::Pending::config(unsigned cfg)
{
  l4_uint32_t old, nv;
  do
    {
      old = cxx::access_once(&_state);
      nv = config_bfm_t::set_dirty(old, cfg);
      if (old == nv)
        return false;
    }
  while (!mp_cas(&_state, old, nv));
  return true;
}

inline bool
Irq_array::Pending::target(unsigned char tgt)
{
  l4_uint32_t old, nv;
  do
    {
      old = cxx::access_once(&_state);
      nv = target_bfm_t::set_dirty(old, tgt);
      if (old == nv)
        return false;
    }
  while (!mp_cas(&_state, old, nv));
  return true;
}


///////////////////////////////////////////////////////////////////////////////
// GIC CPU interface
class Cpu
{
public:
  enum { Num_local = 32 };
  enum { Num_lrs = 4 };

  Cpu() : _local_irq(Num_local) {}
  void setup(unsigned cpuid, Irq_array *spis);

  Irq_array::Irq local_irq(unsigned irqn) { return _local_irq[irqn]; }

  unsigned get_empty_lr() const
  { return __builtin_ffs(_vgic->elsr[0]); }

  bool pending_irqs() const { return _vgic->elsr[0] != 0xf; }

  Irq_array::Irq irq(unsigned irqn);
  Irq_array::Const_irq irq(unsigned irqn) const;

  Vmm::Arm::State::Gic *vgic() const { return _vgic; }
  void vgic(Vmm::Arm::State::Gic *gic) { _vgic = gic; }

  l4_uint32_t read_sgi_pend(unsigned reg)
  { return _sgi_pend[reg]; }

  void write_set_sgi_pend(unsigned reg, l4_uint32_t value);
  void write_clear_sgi_pend(unsigned reg, l4_uint32_t value);
  void handle_eois();
  bool add_pending_irq(unsigned lr, Irq_array::Irq const &irq, unsigned irq_id, unsigned src_cpu = 0);
  bool inject(Irq_array::Irq const &irq, unsigned irq_id, unsigned src_cpu = 0);
  void handle_maintenance_irq(unsigned current_cpu);

  void set_work_pending()
  { cxx::write_now(&_pending_work, true); }

  bool is_work_pending() const
  { return cxx::access_once(&_pending_work); }

private:
  Irq_array _local_irq;
  Irq_array *_spis;
  l4_uint32_t _sgi_pend[4]; // 4 * 4 == 16 SGIs a 8 bits
  Vmm::Arm::State::Gic *_vgic;
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
    return (*_spis)[irqn- Num_local];
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
  if (0)
    printf("GICC(%p): _vgic=%p\n", this, _vgic);
  unsigned ridx = 0;
  // currently we use up to 32 list registers
  l4_uint32_t eisr = _vgic->eisr[ridx];
  if (!eisr)
    return;

  for (unsigned i = 0; i < Num_lrs; ++i, eisr >>= 1)
    {
      if (!(eisr & 1))
        continue;

      Irq_array::Irq c = irq(_vgic->lr[i].vid());
      _vgic->lr[i] = Vmm::Arm::Gic_h::Lr(0);
      _vgic->elsr[ridx] |= (1 << i); // maintain our SW state
      c.do_eoi();
      c.eoi(vmm_current_cpu_id);
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
  irq.set_lr(lr);
  _vgic->lr[lr] = new_lr;
  _vgic->elsr[0] &= ~(1UL << lr);
  return true;
}


inline bool
Cpu::inject(Irq_array::Irq const &irq, unsigned irq_id, unsigned src_cpu)
{
  using Vmm::Arm::Gic_h::Lr;

  handle_eois();

  // look for an empty list register
  unsigned lr_idx = get_empty_lr();
  // currently we use up to 32 list registers
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
          printf("VGIC full: ");
          for (unsigned i = 0; i < Num_lrs; ++i)
            printf("%d: %x ", i, _vgic->lr[i].raw);
          printf("\n");

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


  static Reg_group_info const reg_group[10];

  Irq_array::Irq spi(unsigned spi)
  {
    assert (spi < tnlines * 32);
    return _spis[spi];
  }

  Irq_array::Irq ppi(unsigned ppi, unsigned cpu)
  {
    assert (ppi < 32);
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

  void bind_irq_source(unsigned irq, cxx::Ref_ptr<Irq_source> src) override
  { spi(irq - Cpu::Num_local).set_eoi(src); }

  int dt_get_num_interrupts(Vdev::Dt_node const &node)
  {
    int size;
    auto prop = node.get_prop<fdt32_t>("interrupts", &size);

    return prop ? (size / Irq_cells) : 0;
  }

  unsigned dt_get_interrupt(Vdev::Dt_node const &node, int irq)
  {
    auto *prop = node.check_prop<fdt32_t[Irq_cells]>("interrupts", irq + 1);

    int irqnr = fdt32_to_cpu(prop[irq][Irq_cell_number]);

    if (fdt32_to_cpu(prop[irq][Irq_cell_type]) == 0)
      return irqnr + Irq_spi_base;

    if (irqnr >= Irq_ppi_max)
      L4Re::chksys(-L4_EINVAL, "Only 16 PPI interrupts allowed");

    return irqnr + Irq_ppi_base;
  }

  void init_device(Vdev::Device_lookup const *,
                   Vdev::Dt_node const &) override
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

  void irq_mmio_write(Irq_array::Irq const &irq, unsigned /*irq_id*/,
                      unsigned rgroup, l4_uint32_t value)
  {
    switch (rgroup)
      {
      case R_group:    irq.group(value);               return;
      case R_isenable: irq.enable(true);               return;
      case R_icenable: irq.enable(false);              return;
      case R_ispend:   irq.pending(true);              return;
      case R_icpend:   irq.pending(false);             return;
      case R_isactive: irq.active(true);               return;
      case R_icactive: irq.active(false);              return;
      case R_prio:     irq.prio((value >> 3) & 0x1f);  return;
      case R_target:   irq.target(value);              return;
      case R_cfg:      irq.config(value);              return;
      default:         assert (false);                 return;
      }
  }

  void notify_cpus(unsigned mask)
  {
    if (0)
      gicd_info.printf("Do notify other CPUs to do IRQ work: %x\n", mask);
  }

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
          printf("Warn: IRQ for different CPU: %d\n", id);

        if (unsigned char map = (irq.target() & ~current_cpu & active_mask))
          notify_cpus(map);
      }
    else
      {
        if (0)
           printf("PI: id=%d %s%s %x %d %d\n",
                  id, irq.pending() ? "pending " : "",
                  irq.enabled() ? "enabled " : "",
                  (unsigned)irq.target(), (int)irq.cpu(), (int)irq.prio());
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

  void set_cpu(unsigned cpu, Vmm::Arm::State::Gic *iface)
  {
    gicd_info.printf("set CPU interface for CPU %02d (%p) to %p\n",
                     cpu, &_cpu[cpu], iface);
    if (cpu >= cpus)
      return;

    using namespace Vmm::Arm;
    _cpu[cpu].vgic(iface);
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

    int pmask = c->vgic()->vmcr.pri_mask() << 3;

    for (;;)
      {
        unsigned empty_lr = c->get_empty_lr();

        if (!empty_lr)
          return true;

        int spi = _spis.find_pending_irq(1 << current_cpu,
                                         pmask, 0, tnlines * 32);
        if (spi < 0)
          return c->pending_irqs();
        if (0)
          gicd_info.printf("Try to inject: irq=%d on cpu=%d... ",
                           spi + 32, current_cpu);
        bool ok = c->add_pending_irq(empty_lr - 1, _spis[spi], spi + 32);
        if (0)
          gicd_info.printf("%s\n", ok ? "OK" : "FAILED");
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
        atomic_or(&_active_grp0_cpus, (1UL << current_cpu));
        hcr.vgrp0_eie() = 0;
        hcr.vgrp0_die() = 1;
      }

    if (misr.grp0_d())
      {
        atomic_and(&_active_grp0_cpus, ~(1UL << current_cpu));
        hcr.vgrp0_eie() = 1;
        hcr.vgrp0_die() = 0;
      }

    if (misr.grp1_e())
      {
        atomic_or(&_active_grp1_cpus, (1UL << current_cpu));
        hcr.vgrp1_eie() = 0;
        hcr.vgrp1_die() = 1;
      }

    if (misr.grp1_d())
      {
        atomic_and(&_active_grp1_cpus, ~(1UL << current_cpu));
        hcr.vgrp1_eie() = 1;
        hcr.vgrp1_die() = 0;
      }

    c->handle_maintenance_irq(current_cpu);
  }

private:
  unsigned char _active_grp0_cpus;
  unsigned char _active_grp1_cpus;
  cxx::unique_ptr<Cpu[]> _cpu;
  Irq_array _spis;
};

}
