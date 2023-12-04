/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020-2022 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "gic-v3.h"

namespace Gic {

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
          _redist_cpu[cif->vcpu_id()].ctlr(_dist->num_lpi_bits(),
                                           *_dist->_ram.get(), value);
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

  Redist_cpu *cpu(unsigned cpu_id)
  {
    return cpu_id < _redist_cpu.size() ? &_redist_cpu[cpu_id] : nullptr;
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

  char const *dev_name() const override { return "Redist"; }
};

class Sgir_sysreg : public Vmm::Arm::Sys_reg
{
private:
  void bcast(unsigned intid)
  {
    auto const &cc = dist->_cpu[vmm_current_cpu_id];
    for (auto const &c: dist->_cpu)
      if (c != cc)
        dist->inject_irq(c->local_irq(intid), cc.get());
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
          dist->inject_irq(c->local_irq(intid), cc.get());
        else
          dist->inject_irq_local(c->local_irq(intid), cc.get());
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

Dist_v3::Dist_v3(unsigned tnlines)
: Dist(tnlines, Num_cpus),
  _router(cxx::make_unique<l4_uint64_t[]>(32 * tnlines)),
  _redist(new Redist(this)),
  _redist_size(0),
  _sgir(new Sgir_sysreg(this))
{
  ctlr = Gicd_ctlr_must_set;
}

void
Dist_v3::setup_cpu(Vmm::Vcpu_ptr vcpu)
{
  auto *c = Dist::add_cpu(vcpu);
  if (!c)
    return;

  if ((_redist_size >> Redist::Stride) < _cpu.size())
    {
      Err().printf("GICR mmio is too small for %u+ cpus: 0x%llx.\n",
                   _cpu.size(), _redist_size);
      L4Re::throw_error(-L4_EINVAL, "Setup GICv3 redistributor");
    }

  for (unsigned i = 0; i < Cpu::Num_local; ++i)
    c->local_irq(i).target(0, c);

  redist(vcpu.get_vcpu_id())->ipc_registry(vcpu.get_ipc_registry());
}

l4_uint32_t
Dist_v3::get_typer() const
{
  // CPUNumber: ARE always enabled, see also GICD_CTLR.
  // No1N:      1 of N SPI routing model not supported
  l4_uint32_t type = tnlines | (0 << 5) | (1 << 25);

  unsigned lpi_bits = num_lpi_bits();
  if (lpi_bits > 0)
    {
      // IDBits: 14+ (IDs 0-1019, 1020-1023 are reserved,
      //              LPIs 8192-(8192 + 2^lpi_bits)).
      unsigned id_bits = 13 + cxx::max(1, static_cast<int>(lpi_bits) - 12);
      type |= ((lpi_bits - 1) << 11) // Number of supported LPI bits minus one.
              | (1 << 17)            // LPIs are supported
              | ((id_bits - 1) << 19); // Number of IDBits minus one.
    }
  else
    {
      // IDBits: 10 (IDs 0-1019, 1020-1023 are reserved).
      type |= (9 << 19);
    }
  return type;
}

Redist_cpu *
Dist_v3::redist(unsigned cpu_id)
{
  return static_cast<Redist *>(_redist.get())->cpu(cpu_id);
}

Redist_cpu const *
Dist_v3::redist(unsigned cpu_id) const
{
  return static_cast<Redist *>(_redist.get())->cpu(cpu_id);
}

cxx::Ref_ptr<Vdev::Device>
Dist_v3::setup_gic(Vdev::Device_lookup *devs, Vdev::Dt_node const &node)
{
  _ram = devs->ram();

  cxx::Ref_ptr<Dist_v3> self(this);
  l4_uint64_t base;

  int res = node.get_reg_val(1, &base, &_redist_size);
  if (res < 0)
    {
      Err().printf("Failed to read 'reg[1]' from node %s: %s\n",
                   node.get_name(), node.strerror(res));
      L4Re::throw_error(-L4_EINVAL, "Setup GICv3");
    }

  if (base & 0xffff)
    {
      Err().printf("%s: GICR mmio is not 64K aligned: <%llx, %llx>.\n",
                   node.get_name(), base, _redist_size);
      L4Re::throw_error(-L4_EINVAL, "Setup GICv3");
    }

  devs->vmm()->register_mmio_device(_redist, Vmm::Region_type::Virtual, node,
                                    1);
  devs->vmm()->register_mmio_device(self, Vmm::Region_type::Virtual, node);

  devs->vmm()->add_sys_reg_aarch64(3, 0, 12, 11, 5, _sgir);
  devs->vmm()->add_sys_reg_aarch32_cp64(15, 0, 12, _sgir);

  node.setprop_string("compatible", "arm,gic-v3");

  return self;
}

namespace {

struct DF : Dist<true>::Factory
{
  DF() : Factory(3) {}
  cxx::Ref_ptr<Dist_if> create(unsigned tnlines) const
  {
    return Vdev::make_device<Dist_v3>(tnlines);
  }
};

static DF df;

}

} // Gic
