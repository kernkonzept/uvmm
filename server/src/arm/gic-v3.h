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

/**
 * Per vCPU redistributor state.
 */
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
      return lpis > Cpu::Lpi_base ? lpis - Cpu::Lpi_base : 0;
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

  void ctlr(unsigned num_lpi_bits, Vmm::Vm_ram const &ram, l4_uint32_t ctrl)
  {
    // Once LPI support has been enabled, it cannot be disabled again.
    if (num_lpi_bits > 0 && !lpis_enabled() && (ctrl & GICR_CTRL_enable_lpi))
      enable_lpis(num_lpi_bits, ram);
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

  Vcpu_obj_registry *ipc_registry() const
  { return _registry; }

  void ipc_registry(Vcpu_obj_registry *registry)
  { _registry = registry; }

private:
  void enable_lpis(unsigned num_lpi_bits, Vmm::Vm_ram const &ram)
  {
    // If number of LPIs configured in Propbaser is larger the number of LPIs
    // supported by the distributor, the distributor's limit applies.
    _num_lpis = cxx::min(_propbase.num_lpis(), 1u << num_lpi_bits);
    _config_table = ram.guest2host<Lpi_config *>(
      Vmm::Region::ss(Vmm::Guest_addr(_propbase.pa()), _num_lpis,
                      Vmm::Region_type::Ram));

    // Incomplete: For now, we do not support setting the initial pending
    // state of LPIs via the pendbase register.

    _lpis_enabled.store(true, std::memory_order_release);
  }

  Vcpu_obj_registry *_registry = nullptr;
  std::atomic<bool> _lpis_enabled = { false };
  Gic_mem_reg<Propbaser> _propbase;
  Gic_mem_reg<Pendbaser> _pendbase;
  unsigned _num_lpis = 0;
  Lpi_config *_config_table = nullptr;
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
  friend class Redist;
  friend class Sgir_sysreg;

private:
  cxx::Ref_ptr<Vmm::Vm_ram> _ram;
  cxx::unique_ptr<l4_uint64_t[]> _router;
  cxx::Ref_ptr<Mmio_device> _redist;
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

  Redist_cpu *redist(unsigned cpu_id);
  Redist_cpu const *redist(unsigned cpu_id) const;

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

    if (reg >= 0x6100
        && (reg < (0x6100 + 8 * 32 * static_cast<unsigned>(tnlines))))
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
    if (reg >= 0x6100
        && (reg < (0x6100 + 8 * 32 * static_cast<unsigned>(tnlines))))
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

  char const *dev_name() const override { return "Dist_v3"; }
};

}
