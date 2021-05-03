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
#include "mem_access.h"

namespace {
using namespace Gic;

class Redist_cpu
{
private:
#if 0 // we have no LPI support yet ...
  l4_uint32_t _ctlr;
  l4_uint64_t _propbase;
  l4_uint64_t _pendbase;
#endif

};

struct Cpu_if_v3
{
  struct Lr
  {
    enum State
    {
      Empty              = 0,
      Pending            = 1,
      Active             = 2,
      Active_and_pending = 3
    };

    l4_uint64_t raw;
    Lr() = default;
    explicit Lr(l4_uint64_t v) : raw(v) {}
    CXX_BITFIELD_MEMBER(  0, 31, vid, raw);
    CXX_BITFIELD_MEMBER( 32, 41, pid, raw);
    CXX_BITFIELD_MEMBER( 41, 41, eoi, raw);
    CXX_BITFIELD_MEMBER( 48, 55, prio, raw);
    CXX_BITFIELD_MEMBER( 60, 60, grp1, raw);
    CXX_BITFIELD_MEMBER( 61, 61, hw, raw);
    CXX_BITFIELD_MEMBER( 62, 63, state, raw);
    CXX_BITFIELD_MEMBER( 62, 62, pending, raw);
    CXX_BITFIELD_MEMBER( 63, 63, active, raw);

    void set_cpuid(unsigned) {}
  };

  static Lr read_lr(Vmm::Vcpu_ptr vcpu, unsigned idx)
  {
    return Lr(l4_vcpu_e_read_64(*vcpu, L4_VCPU_E_GIC_V3_LR0 + idx * 8));
  }

  static void write_lr(Vmm::Vcpu_ptr vcpu, unsigned idx, Lr lr)
  { l4_vcpu_e_write_64(*vcpu, L4_VCPU_E_GIC_V3_LR0 + idx * 8, lr.raw); }

  static unsigned pri_mask(Vmm::Vcpu_ptr vcpu)
  {
    l4_uint32_t v = l4_vcpu_e_read_32(*vcpu, L4_VCPU_E_GIC_VMCR);
    return (v >> 24);
  }
};

class Dist_v3 : public Dist_mixin<Dist_v3>
{
private:
  using Dist = Dist_mixin<Dist_v3>;

  class Redist : public Vmm::Mmio_device_t<Redist>
  {
  private:
    Dist_v3 *_dist;

    enum
    {
      IID  = 0x43b,
      IID2 = 3 << 4,
      TYPE = 0x0, // all but proc_num and affinity and last...
    };

    l4_uint32_t ctlr() const
    {
      return 0;
    }

    void ctlr(l4_uint32_t)
    {}

    l4_uint64_t porpbase() const
    { return 0; }

    void porpbase(l4_uint64_t) const
    {}

    l4_uint64_t pendbase() const
    { return 0; }

    void pendbase(l4_uint64_t) const
    {}

    l4_uint32_t status() const
    { return 0; }

    void status(l4_uint32_t) const
    {}

    enum
    {
      CTLR    = 0x0,
      IIDR    = 0x4,
      TYPER   = 0x8,
      STATUSR = 0x10,
      WAKER   = 0x14,
      IIDR2   = 0xffe8,
    };

    l4_uint64_t read_rd(Cpu *cif, unsigned reg, char size, bool last)
    {
      unsigned r32 = reg & ~3u;
      using Ma = Vmm::Mem_access;

      switch (r32)
        {
        case CTLR:
          return ctlr();

        case IIDR:
          return IID;

        case IIDR2:
          return IID2;

        case TYPER: /* fall-through */
        case TYPER + 4:
          return Ma::read(TYPE | cif->get_typer() | (last ? 0x10 : 0x00),
                          reg, size);
        case STATUSR:
          return status();

        case WAKER:
          return 0;

        default:
          break;
        }

      return 0;
    }

    void write_rd(Cpu *, unsigned reg, char size, l4_uint64_t value)
    {
      (void) size;
      unsigned r32 = reg & ~3u;
      switch (r32)
        {
        case CTLR:
          ctlr(value);
          return;

        case STATUSR:
          status(value);
          return;

        case WAKER:
          return;

        default:
          break;
        }
      return;
    }

  public:
    enum
    {
      Stride = 17, // 17bit stride -> 2 64K regions RD + SGI
    };

    explicit Redist(Dist_v3 *dist)
    : _dist(dist)
    {}

    l4_uint64_t read(unsigned reg, char size, unsigned)
    {
      unsigned cpu_id = reg >> Stride;
      if (cpu_id >= _dist->_cpu.size())
        return 0;

      unsigned blk = (reg >> 16) & ~((~0u) << (Stride - 16));
      reg &= 0xffff;

      l4_uint64_t res = 0;
      switch (blk)
        {
          case 0:
            return read_rd(_dist->_cpu[cpu_id].get(), reg, size,
                           cpu_id + 1 == _dist->_cpu.size());
          case 1:
            _dist->read_multi_irq(reg, size, cpu_id, &res);
            return res;
          default:
            return 0;
        }
    }

    void write(unsigned reg, char size, l4_uint64_t value, unsigned)
    {
      unsigned cpu_id = reg >> Stride;
      if (cpu_id >= _dist->_cpu.size())
        return;

      unsigned blk = (reg >> 16) & ~((~0u) << (Stride - 16));
      reg &= 0xffff;
      switch (blk)
        {
          case 0:
            return write_rd(_dist->_cpu[cpu_id].get(), reg, size, value);
          case 1:
            _dist->write_multi_irq(reg, size, value, cpu_id);
            return;
          default:
            break;
        }
    }
  };

  class Sgir_sysreg : public Vmm::Arm::Sys_reg
  {
  private:
    void bcast(unsigned intid)
    {
      auto const &cc = dist->_cpu[vmm_current_cpu_id];
      for (auto const &c: dist->_cpu)
        if (c != cc)
          dist->inject_irq_remote(c->local_irq(intid), c.get());
    }

    void sgi_tgt(unsigned intid, l4_uint64_t target)
    {
      unsigned const aff = ((target >> 16) & 0xff)
                           | ((target >> 24) & 0xff00)
                           | ((target >> 32) & 0xff0000);

      unsigned const tgtlist = target & 0xffff;

      auto const &cc = dist->_cpu[vmm_current_cpu_id];
      for (auto const &c: dist->_cpu)
        {
          unsigned a = c->affinity();
          if ((a >> 8) != aff || ((a & 0xff) > 0xf))
            continue;

          if (!((1u << (a & 0xf)) & tgtlist))
            continue;

          if (cc != c)
            dist->inject_irq_remote(c->local_irq(intid), c.get());
          else
            dist->inject_irq_local(c->local_irq(intid), intid, c.get());
        }
    }

  public:
    Dist_v3 *dist;

    explicit Sgir_sysreg(Dist_v3 *d) : dist(d) {}

    l4_uint64_t read(Vmm::Vcpu_ptr, Key) override
    { return 0; }

    void write(Vmm::Vcpu_ptr, Key, l4_uint64_t val) override
    {
      unsigned const intid = (val >> 24) & 0xf;

      if (! (val & (1ull << 40)))
        sgi_tgt(intid, val);
      else
        bcast(intid);
    }
  };

  cxx::unique_ptr<l4_uint64_t[]> _router;
  Redist _redist;
  Sgir_sysreg _sgir;

  enum { Gicd_ctlr_must_set = 5UL << 4 }; // DS, ARE

public:
  using Cpu_if = Cpu_if_v3;

  static bool sgi_pend_regs() { return false; }

  explicit Dist_v3(unsigned tnlines)
  : Dist(tnlines, 255),
    _router(cxx::make_unique<l4_uint64_t[]>(32 * tnlines)),
    _redist(this), _sgir(this)
  {
    ctlr = Gicd_ctlr_must_set;
    _redist.add_ref(); // we keep always a ref to our redist :)
  }

  void setup_cpu(Vmm::Vcpu_ptr vcpu, L4::Cap<L4::Thread> thread) override
  {
    Dist::add_cpu(vcpu, thread);
  }

  l4_uint32_t get_typer() const override
  {
    // CPUNumber: ARE always enabled, see also GICD_CTLR.
    // IDBits:    Let's assume 10 (IDs 0-1019, 1020-1023 are reserved).
    // No1N:      1 of N SPI routing model not supported
    return tnlines
           | (0 << 5)
           | (9 << 19)
           | (1 << 25);
  }

  cxx::Ref_ptr<Vdev::Device>
  setup_gic(Vdev::Device_lookup *devs, Vdev::Dt_node const &node) override
  {
    cxx::Ref_ptr<Dist_v3> self(this);
    cxx::Ref_ptr<Redist> redist(&_redist);
    l4_uint64_t base, size;

    int res = node.get_reg_val(1, &base, &size);
    if (res < 0)
      {
        Err().printf("Failed to read 'reg[1]' from node %s: %s\n",
                     node.get_name(), node.strerror(res));
        L4Re::throw_error(-L4_EINVAL, "Setup GICv3");
      }

    if (base & 0xffff)
      {
        Err().printf("%s: GICR mmio is not 64K aligned: <%llx, %llx>.\n",
                     node.get_name(), base, size);
        L4Re::throw_error(-L4_EINVAL, "Setup GICv3");
      }

    if ((size >> Redist::Stride) < _cpu.size())
      {
        Err().printf("%s: GICR mmio is too small for %u cpus: <%llx, %llx>.\n",
                     node.get_name(), _cpu.size(), base, size);
        L4Re::throw_error(-L4_EINVAL, "Setup GICv3");
      }

    devs->vmm()->register_mmio_device(redist, Vmm::Region_type::Virtual, node, 1);
    devs->vmm()->register_mmio_device(self, Vmm::Region_type::Virtual, node);

    _sgir.add_ref(); // we aggregate this so count our own reference
    devs->vmm()->add_sys_reg_aarch64(3, 0, 12, 11, 5, cxx::ref_ptr(&_sgir));
    devs->vmm()->add_sys_reg_aarch32_cp64(15, 0, 12, cxx::ref_ptr(&_sgir));

    node.setprop_string("compatible", "arm,gic-v3");

    return self;
  }

  void update_gicc_state(Vmm::Arm::Gic_h::Misr, unsigned)
  {}

  void inject_local(unsigned id, unsigned current_cpu)
  {
    Cpu *cpu = _cpu[current_cpu].get();
    Irq const &irq = cpu->local_irq(id);
    if (irq.pending(true))
      {
        // need to take some action to pass IRQ to a CPU
        cpu->inject<Cpu_if>(irq, id);
      }
  }

  void inject_irq_remote(Irq const &irq, Cpu *target)
  {
    if (irq.pending(true))
      target->notify();
  }

  void inject_irq_local(Irq const &irq, unsigned id, Cpu *c)
  {
    if (irq.pending(true))
      c->inject<Cpu_if>(irq, id);
  }

  void inject_irq(Irq const &irq, unsigned id, unsigned current_cpu)
  {
    unsigned tgt = irq.target();
    if (tgt != current_cpu)
      inject_irq_remote(irq, _cpu[tgt].get());
    else
      inject_irq_local(irq, id, _cpu[current_cpu].get());
  }

  void set(unsigned irq) override
  {
    if (irq < Cpu::Num_local)
      inject_local(irq, vmm_current_cpu_id);
    else
      inject_irq(this->spi(irq - Cpu::Num_local), irq, vmm_current_cpu_id); // SPI
  }

  int find_pending_spi(unsigned pmask, unsigned target, Irq *irq)
  {
    return _spis.find_pending_irq(pmask, irq, [target](Irq_info const *i)
        {
          // currently we support no 1 of N delivery
          return i->target() == target;
        });
  }

  void sgir_write(l4_uint32_t)
  {}

  int find_cpu(l4_uint32_t affinity)
  {
    for (unsigned i = 0; i < _cpu.size(); ++i)
      if (_cpu[i]->affinity() == affinity)
        return i;

    return -1;
  }

  l4_uint64_t read(unsigned reg, char size, unsigned cpu_id)
  {
    l4_uint64_t res = 0;
    if (dist_read(reg, size, cpu_id, &res))
      return res;

    if (reg >= 0x6100 && (reg < (0x6100 + 8 * 32 * (unsigned)tnlines)))
      {
        unsigned const r = (reg - 0x6100) >> 3;
        return Vmm::Mem_access::read(_router[r], reg & 7, size);
      }

    return 0;
  }

  l4_uint32_t iidr_read(unsigned r) const override
  {
    if (r == 0x18)
      return 3 << 4; // GICv3

    return 0;
  }

  void write(unsigned reg, char size, l4_uint64_t value, unsigned cpu_id)
  {
    if (dist_write(reg, size, value, cpu_id))
      return;

    if (reg >= 0x6100 && (reg < (0x6100 + 8 * 32 * (unsigned)tnlines)))
      {
        unsigned const r = (reg - 0x6100) >> 3;
        Vmm::Mem_access::write(&_router[r], value, reg & 7, size);
        _router[r] &= ~(1ull << 31); // IRM always 0: no 1 of N routing
        l4_uint32_t aff =   (_router[r] & 0x00ffffff)
                          | ((_router[r] >> 32) & 0xff000000);
        spi(r).target(find_cpu(aff));
      }
  }

  void write_ctlr(l4_uint32_t val) override
  {
    ctlr = (val & 3U) | Gicd_ctlr_must_set;
  }
};

struct DF : Dist::Factory
{
  DF() : Factory(3) {}
  cxx::Ref_ptr<Dist_if> create(unsigned tnlines) const
  {
    return Vdev::make_device<Dist_v3>(tnlines);
  }
};

static DF df;
}
