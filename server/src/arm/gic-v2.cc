/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2020 Kernkonzept GmbH.
 * Author(s): Alexander Warg <alexander.warg@kernkonzept.com>
 *
 */

#include "gic_cpu.h"
#include "gic_mixin.h"
#include "guest.h"
#include "mem_types.h"

namespace {

using namespace Vdev;

/**
 * Mmio access handler that maps the GICC page.
 *
 * This handler maps the page during the eager-mapping stage before the
 * guest is started. It is also able to respond to page faults in the region
 * and will map the page again. Note, however, that this should normally
 * not happen because the page is pinned in the VM task during its life time.
 * Therefore a warning is printed when the access() function is called.
 */
class Gicc_region_mapper : public Vmm::Mmio_device
{
public:
  Gicc_region_mapper(l4_addr_t base)
  : _fp(l4_fpage(base, L4_PAGESHIFT, L4_FPAGE_RW))
  {}

  int access(l4_addr_t, l4_addr_t, Vmm::Vcpu_ptr,
             L4::Cap<L4::Vm> vm, l4_addr_t, l4_addr_t) override
  {
    Dbg(Dbg::Core, Dbg::Warn)
      .printf("Access to GICC page trapped into guest handler. Restoring mapping.\n");

    remap_page(vm);

    return Vmm::Retry;
  }

  void map_eager(L4::Cap<L4::Vm> vm, Vmm::Guest_addr, Vmm::Guest_addr) override
  { remap_page(vm); }

  static l4_uint64_t
  verify_node(Vdev::Dt_node const &node)
  {
    l4_uint64_t base, size;
    int res = node.get_reg_val(1, &base, &size);
    if (res < 0)
      {
        Err().printf("Failed to read 'reg[1]' from node %s: %s\n",
                     node.get_name(), node.strerror(res));
        throw L4::Runtime_error(-L4_EINVAL,
                                "Reading device tree entry for GIC");
      }

    // Check the alignment of the GICC page
    if (base & (L4_PAGESIZE - 1))
      {
        Err().printf("%s:The GICC page is not page aligned: <%llx, %llx>.\n",
                     node.get_name(), base, size);
        L4Re::chksys(-L4_EINVAL, "Setting up GICC page");
      }

    if (size > L4_PAGESIZE)
      {
        Dbg(Dbg::Irq, Dbg::Info, "GIC")
          .printf("GIC %s.reg update: Adjusting GICC size from %llx to %lx\n",
                  node.get_name(), size, L4_PAGESIZE);
        node.update_reg_size(1, L4_PAGESIZE);
      }

    // Check if there are more than two "reg" entries (VGIC registers)
    if (node.get_reg_size_flags(2, nullptr, nullptr) == 0)
      {
        Dbg(Dbg::Irq, Dbg::Info, "GIC")
          .printf("GIC %s.reg update: Stripping superfluous entries\n",
                  node.get_name());
        node.resize_reg(2);
      }

    return base;
  }

  char const *dev_name() const override { return "Gicc"; };

  static void map_gicc(Device_lookup *devs, Vdev::Dt_node const &node)
  {
    l4_uint64_t base = Gicc_region_mapper::verify_node(node);
    auto gerr = Vdev::make_device<Gicc_region_mapper>(base);
    devs->vmm()->register_mmio_device(cxx::move(gerr), Vmm::Region_type::Kernel,
                                      node, 1);
  }

private:
  void remap_page(L4::Cap<L4::Vm> vm) const
  {
    Dbg(Dbg::Mmio, Dbg::Info, "mmio")
      .printf("\tMapping [GICC] -> [%lx - %lx]\n", l4_fpage_memaddr(_fp),
              l4_fpage_memaddr(_fp) + L4_PAGESIZE - 1);
    L4Re::chksys(vm->vgicc_map(_fp), "Mapping VGICC area into guest task");
  }

  l4_fpage_t _fp;
};

using namespace Gic;

/**
 * GICv2 Distributor implementation.
 */
class Dist_v2 : public Dist_mixin<Dist_v2, false>
{
private:
  using Dist = Dist_mixin<Dist_v2, false>;

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

  void setup_cpu(Vmm::Vcpu_ptr vcpu) override
  {
    auto *c = Dist::add_cpu(vcpu);
    if (!c)
      return;

    unsigned id = vcpu.get_vcpu_id();
    for (unsigned i = 0; i < 32; ++i)
      c->local_irq(i).target(1u << id, c);
  }

  /// setup the mappings for a GICv2 distributor and CPU interface in the VM
  cxx::Ref_ptr<Vdev::Device>
  setup_gic(Vdev::Device_lookup *devs, Vdev::Dt_node const &node) override
  {
    cxx::Ref_ptr<Dist_v2> self(this);
    // attach GICD to VM
    devs->vmm()->register_mmio_device(self, Vmm::Region_type::Virtual, node);
    // attach GICC to VM
    Gicc_region_mapper::map_gicc(devs, node);

    node.setprop_string("compatible", "arm,gic-400");
    return self;
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
            set(irq);
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

  char const *dev_name() const override { return "Dist_v2"; }
};

struct DF : Dist<false>::Factory
{
  DF() : Factory(2) {}
  cxx::Ref_ptr<Dist_if> create(unsigned tnlines) const
  {
    return Vdev::make_device<Dist_v2>(tnlines);
  }
};

static DF df;

}
