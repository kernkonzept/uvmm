/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2022 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include <atomic>

#include "gic_cpu.h"
#include "gic_mixin.h"
#include "guest.h"
#include "mem_types.h"
#include "mem_access.h"

namespace Gic {

/**
 * Abstraction for a GIC register that allows the guest to setup a shared memory
 * area with the GIC. This class provides the following functionality:
 *  - Enforce the memory attributes in the register to be inner shareable and
 *    cacheable.
 *  - Allow also non-64-bit sized accesses to the register.
 *  - Custom read-only fields.
 */
template<typename REG>
struct Gic_mem_reg : public REG
{
  enum
  {
    Share_inner_shareable        = 1,
    Inner_cache_cacheable_rawawb = 7,
    Outer_cache_same_as_inner    = 0,

    Ro_mask = REG::Ro_mask | REG::share_bfm_t::Mask
              | REG::inner_cache_bfm_t::Mask | REG::outer_cache_bfm_t::Mask,
  };

  template<typename... Args>
  Gic_mem_reg(Args &&... args)
  : REG(cxx::forward<Args>(args)...)
  {
    REG::share() = Share_inner_shareable;
    REG::inner_cache() = Inner_cache_cacheable_rawawb;
    REG::outer_cache() = Outer_cache_same_as_inner;
  }

  l4_uint64_t read(unsigned reg, unsigned size)
  {
    return Vmm::Mem_access::read(REG::raw, reg, size);
  }

  void write(l4_uint64_t value, unsigned reg, char size)
  {
    l4_uint64_t tmp = REG::raw;
    Vmm::Mem_access::write(&tmp, value, reg, size);
    REG::raw = (REG::raw & Ro_mask) | (tmp & ~Ro_mask);
  }
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

class Dist_v3 : public Dist_mixin<Dist_v3, true>
{
private:
  using Dist = Dist_mixin<Dist_v3, true>;
  friend class Sgir_sysreg;

public:
  class Redist_cpu
  {
  private:
    enum
    {
      GICR_CTRL_enable_lpi = 1 << 0,
    };

    struct Lpi_config
    {
      l4_uint8_t raw;
      CXX_BITFIELD_MEMBER          (0, 0, enable, raw);
      CXX_BITFIELD_MEMBER_UNSHIFTED(2, 7, priority, raw);
    };

    struct Propbaser
    {
      l4_uint64_t raw = 0;
      CXX_BITFIELD_MEMBER          ( 0,  4, id_bits, raw);
      CXX_BITFIELD_MEMBER          ( 7,  9, inner_cache, raw);
      CXX_BITFIELD_MEMBER          (10, 11, share, raw);
      CXX_BITFIELD_MEMBER_UNSHIFTED(12, 51, pa, raw);
      CXX_BITFIELD_MEMBER          (56, 58, outer_cache, raw);

      enum { Ro_mask = 0 };

      unsigned num_lpis()
      {
        unsigned lpis = (1 << (id_bits() + 1));
        return lpis > Lpi_base ? lpis - Lpi_base : 0;
      }
    };

    struct Pendbaser
    {
      l4_uint64_t raw = 0;
      CXX_BITFIELD_MEMBER          ( 7,  9, inner_cache, raw);
      CXX_BITFIELD_MEMBER          (10, 11, share, raw);
      CXX_BITFIELD_MEMBER_UNSHIFTED(16, 51, pa, raw);
      CXX_BITFIELD_MEMBER          (56, 58, outer_cache, raw);
      CXX_BITFIELD_MEMBER          (62, 62, ptz, raw);

      enum { Ro_mask = 0 };
    };

  public:
    l4_uint32_t ctlr() const
    { return lpis_enabled() ? GICR_CTRL_enable_lpi : 0; }

    void ctlr(Dist_v3 *dist, l4_uint32_t ctrl)
    {
      // Once LPI support has been enabled, it cannot be disabled again.
      if (dist->_lpis && !lpis_enabled() && (ctrl & GICR_CTRL_enable_lpi))
        enable_lpis(dist);
    }

    l4_uint64_t propbase() const
    { return _propbase.raw; }

    void propbase(unsigned reg, char size, l4_uint64_t value)
    {
      if (!lpis_enabled())
        _propbase.write(value, reg, size);
    }

    l4_uint64_t pendbase() const
    { return _pendbase.raw; }

    void pendbase(unsigned reg, char size, l4_uint64_t value)
    {
      if (!lpis_enabled())
        _pendbase.write(value, reg, size);
    }

    bool lpis_enabled() const
    { return _lpis_enabled.load(std::memory_order_acquire); }

    /**
     * Return whether the LPI is enabled in the LPI configuration table.
     *
     * \pre Must only be called after checking lpis_enabled() == true.
     */
    bool lpi_enabled(unsigned lpi) const
    { return lpi < _num_lpis && _config_table[lpi].enable(); }

    /**
     * Return the priority configured for LPI in the LPI configuration table.
     *
     * \pre Must only be called after checking lpis_enabled() == true.
     */
    l4_uint8_t lpi_priority(unsigned lpi) const
    {
      return lpi < _num_lpis ? _config_table[lpi].priority() : 0;
    }

  private:
    void enable_lpis(Dist_v3 *dist)
    {
      // If number of LPIs configured in Propbaser is larger the number of LPIs
      // supported by the distributor, the distributor's limit applies.
      _num_lpis = cxx::min(_propbase.num_lpis(), 1u << dist->num_lpi_bits());
      _config_table = dist->_ram->guest2host<Lpi_config *>(
        Vmm::Region::ss(Vmm::Guest_addr(_propbase.pa()), _num_lpis,
                        Vmm::Region_type::Ram));

      // Incomplete: For now, we do not support setting the initial pending
      // state of LPIs via the pendbase register.

      _lpis_enabled.store(true, std::memory_order_release);
    }

    std::atomic<bool> _lpis_enabled = { false };
    Gic_mem_reg<Propbaser> _propbase;
    Gic_mem_reg<Pendbaser> _pendbase;
    unsigned _num_lpis = 0;
    Lpi_config *_config_table = nullptr;
  };

  class Redist : public Vmm::Mmio_device_t<Redist>
  {
  private:
    Dist_v3 *_dist;

    std::mutex _lock;
    std::vector<Redist_cpu> _redist_cpu;

    enum
    {
      IID  = 0x43b,
      IID2 = 3 << 4,
      // All but proc_num and affinity and last.
      // CommonLPIAff = 0 -> All redistributors must share LPI config table.
      // DirectLPI = 0 -> Direct injection of LPIs not supported.
      TYPE = 0,
    };

    l4_uint32_t status() const
    { return 0; }

    void status(l4_uint32_t) const
    {}

    l4_uint32_t type() const
    {
      l4_uint32_t type = TYPE;
      if (_dist->_lpis)
        type |= 1 << 0; // Physical LPIs are supported
      return type;
    }

    enum
    {
      CTLR      = 0x0,
      IIDR      = 0x4,
      TYPER     = 0x8,
      STATUSR   = 0x10,
      WAKER     = 0x14,
      PROPBASER = 0x70,
      PENDBASER = 0x78,
      IIDR2     = 0xffe8,
    };

    l4_uint64_t read_rd(Cpu *cif, unsigned reg, char size, bool last)
    {
      unsigned r32 = reg & ~3u;
      using Ma = Vmm::Mem_access;

      switch (r32)
        {
        case CTLR:
          {
            std::lock_guard<std::mutex> lock(_lock);
            return _redist_cpu[cif->vcpu_id()].ctlr();
          }

        case IIDR:
          return IID;

        case IIDR2:
          return IID2;

        case TYPER:
        case TYPER + 4:
          return Ma::read(type() | cif->get_typer() | (last ? 0x10 : 0x00),
                          reg, size);
        case STATUSR:
          return status();

        case WAKER:
          return 0;

        case PROPBASER:
        case PROPBASER + 4:
          {
            std::lock_guard<std::mutex> lock(_lock);
            return Ma::read(_redist_cpu[cif->vcpu_id()].propbase(), reg, size);
          }

        case PENDBASER:
        case PENDBASER + 4:
          {
            std::lock_guard<std::mutex> lock(_lock);
            return Ma::read(_redist_cpu[cif->vcpu_id()].pendbase(), reg, size);
          }

        default:
          break;
        }

      return 0;
    }

    void write_rd(Cpu *cif, unsigned reg, char size, l4_uint64_t value)
    {
      unsigned r32 = reg & ~3u;

      switch (r32)
        {
        case CTLR:
          {
            std::lock_guard<std::mutex> lock(_lock);
            _redist_cpu[cif->vcpu_id()].ctlr(_dist, value);
            return;
          }

        case STATUSR:
          status(value);
          return;

        case WAKER:
          return;

        case PROPBASER:
        case PROPBASER + 4:
          {
            std::lock_guard<std::mutex> lock(_lock);
            _redist_cpu[cif->vcpu_id()].propbase(reg, size, value);
            return;
          }

        case PENDBASER:
        case PENDBASER + 4:
          {
            std::lock_guard<std::mutex> lock(_lock);
            _redist_cpu[cif->vcpu_id()].pendbase(reg, size, value);
            return;
          }

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
    : _dist(dist),
      _redist_cpu(_dist->_cpu.capacity())
    {
    }

    Redist_cpu const *cpu(unsigned cpu_id) const
    {
      return cpu_id < _redist_cpu.size() ? &_redist_cpu[cpu_id] : nullptr;
    }

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

  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
  cxx::unique_ptr<l4_uint64_t[]> _router;
  cxx::Ref_ptr<Redist> _redist;
  l4_uint64_t _redist_size;
  cxx::Ref_ptr<Vmm::Arm::Sys_reg> _sgir;

  enum { Gicd_ctlr_must_set = 5UL << 4 }; // DS, ARE

public:
  using Cpu_if = Cpu_if_v3;

  static bool sgi_pend_regs() { return false; }

  enum { Num_cpus = 255 };

  explicit Dist_v3(unsigned tnlines);

  void setup_cpu(Vmm::Vcpu_ptr vcpu) override;

  unsigned num_lpi_bits() const
  {
    if (_lpis && _lpis->size() >= 2)
      // Number of supported LPI bits is the log2 of the LPI array size.
      return (sizeof(unsigned) * 8) - __builtin_clz(_lpis->size()) - 1;
    else
      return 0;
  }

  l4_uint32_t get_typer() const override;

  Redist_cpu const *redist(unsigned cpu_id) const
  {
    return _redist->cpu(cpu_id);
  }

  cxx::Ref_ptr<Vdev::Device> setup_gic(Vdev::Device_lookup *devs,
                                       Vdev::Dt_node const &node) override;

  void sgir_write(l4_uint32_t)
  {}

  unsigned char find_cpu(l4_uint32_t affinity)
  {
    for (unsigned i = 0; i < _cpu.size(); ++i)
      if (_cpu[i] && _cpu[i]->affinity() == affinity)
        return i;

    return Irq::Invalid_cpu;
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

    // GICD_IROUTERn
    if (reg >= 0x6100 && (reg < (0x6100 + 8 * 32 * (unsigned)tnlines)))
      {
        std::lock_guard<std::mutex> lock(_target_lock);

        unsigned const r = (reg - 0x6100) >> 3;
        Vmm::Mem_access::write(&_router[r], value, reg & 7, size);
        _router[r] &= ~(1ull << 31); // IRM always 0: no 1 of N routing
        l4_uint32_t aff =   (_router[r] & 0x00ffffff)
                          | ((_router[r] >> 32) & 0xff000000);
        spi(r).target(0, cpu(find_cpu(aff)));
      }
  }

  void write_ctlr(l4_uint32_t val) override
  {
    ctlr = (val & 3U) | Gicd_ctlr_must_set;
  }
};

}
