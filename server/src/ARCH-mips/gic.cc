/*
 * Copyright (C) 2016 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <cstdio>
#include <functional>

#include <l4/sys/kip.h>

#include "guest.h"
#include "device_factory.h"
#include "device_tree.h"
#include "debug.h"
#include "gic.h"

static Dbg trace(Dbg::Irq, Dbg::Trace, "GIC");
static Dbg warn(Dbg::Irq, Dbg::Warn, "GIC");
static Dbg dbg(Dbg::Irq, Dbg::Info, "GIC");

namespace Gic {

Dist::Dist(Mips_core_ic *core_ic)
: Read_mapped_mmio_device_t(Gic_shared_size),
  _core_ic(core_ic)
{
  static_assert(L4_PAGESIZE <= 16 * 1024, "Maximum supported page size is 16k");

  // set up shared section
  auto *cfg = gic_mem<Gic_config_reg>(Gic_sh_config);
  cfg->raw = 0;
  cfg->numint() = (Num_irqs >> 3) - 1;
  cfg->pvps() = 0;

  // set revision to 4.0, as reported by Baikal board
  *gic_mem<l4_uint32_t>(Gic_sh_revision) = 4 << 8;

  auto *sh = gic_mem<char>(0);

  memset(sh + Gic_sh_int_avail, 0xff, Num_irqs >> 3);
  memset(sh + Gic_sh_pend, 0, Num_irqs >> 3);
}

l4_umword_t
Dist::read(unsigned reg, char size, unsigned cpu_id)
{
  if (size < 2)
    {
      warn.printf("WARNING: read @0x%x with unsupported width %d ignored\n",
                  reg, 8 << size);
      return 0;
    }

  if (reg < Gic_shared_base + Gic_shared_size)
    {
      if (size == 3)
        return *gic_mem<l4_uint64_t>(reg);
      else
        return *gic_mem<l4_uint32_t>(reg);
    }

  if (reg >= Gic_core_other_base && reg < Gic_user_visible_base)
    return read_cpu(reg - Gic_core_other_base, size, _other_cpu);
  if (reg >= Gic_core_local_base && reg < Gic_core_other_base)
    return read_cpu(reg - Gic_core_local_base, size, cpu_id);

  dbg.printf("Reading unknown register @ 0x%x (%d)\n", reg, size);
  return 0;
}

void
Dist::write(unsigned reg, char size, l4_umword_t value, unsigned cpu_id)
{
  if (size < 2)
    {
      warn.printf("WARNING: write @0x%x with unsupported width %d ignored\n",
                  reg, 8 << size);
      return;
    }

  if (reg >= Gic_core_local_base && reg < Gic_core_other_base)
    return write_cpu(reg - Gic_core_local_base, size, value, cpu_id);
  if (reg >= Gic_core_other_base && reg < Gic_user_visible_base)
    return write_cpu(reg - Gic_core_other_base, size, value, _other_cpu);

  // write must be to shared section
  if (reg == Gic_sh_wedge)
    {
      Gic_wedge_reg wedge(value);
      if (wedge.irq() < Num_irqs)
        {
          if (wedge.rw())
            set(wedge.irq());
          else
            clear(wedge.irq());
        }
    }
  else if (reg >= Gic_sh_rmask && reg < Gic_sh_rmask + Num_irqs / 8)
    {
      reset_mask(reg - Gic_sh_rmask, size, value);
    }
  else if (reg >= Gic_sh_smask && reg < Gic_sh_smask + Num_irqs / 8)
    {
      set_mask(reg - Gic_sh_smask, size, value);
    }
  else if (reg >= Gic_sh_pol && reg < Gic_sh_wedge)
    {
      // polarity, edge, dual configuration ignored
      gic_mem_set(reg, size, value);
    }
  else if (reg >= Gic_sh_pin && reg < irq_to_pinreg(Num_irqs))
    {
      gic_mem_set(reg, size, value);
      setup_source(pinreg_to_irq(reg));
    }
  else if (reg >= Gic_sh_map && reg < irq_to_mapreg(Num_irqs))
    {
      gic_mem_set(reg, size, value);
      setup_source(mapreg_to_irq(reg));
    }
  else
    dbg.printf("Writing ignored 0x%lx @ 0x%x (%d)\n", value, reg, size);
}

l4_umword_t
Dist::read_cpu(unsigned reg, char, unsigned cpu_id)
{
  trace.printf("Local read from cpu %d ignored @ 0x%x\n",
               cpu_id, reg);
  return 0;
}

void
Dist::write_cpu(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
{
  trace.printf("Local write to cpu %d ignored 0x%lx @ 0x%x\n",
               cpu_id, value, reg);
}

/** disable interrupts */
void
Dist::reset_mask(unsigned reg, char size, l4_umword_t mask)
{
  assert(reg * 8 < Num_irqs);

  l4_umword_t pending;

  if (size == 3)
    {
      *gic_mem<l4_uint64_t>(Gic_sh_mask + reg) &= ~mask;
      pending = mask & *gic_mem<l4_uint64_t>(Gic_sh_pend + reg);
    }
  else
    {
      *gic_mem<l4_uint32_t>(Gic_sh_mask + reg) &= ~mask;
      pending = ((l4_uint32_t) mask) & *gic_mem<l4_uint32_t>(Gic_sh_pend + reg);
    }

  int irq = reg * 8;

  while (pending)
    {
      if (pending & 1)
        _irq_array[irq]->ack();

      ++irq;
      pending >>= 1;
    }
}

/** enable interrupts */
void
Dist::set_mask(unsigned reg, char size, l4_umword_t mask)
{
  assert(reg * 8 < Num_irqs);

  if (size == 3)
    *gic_mem<l4_uint64_t>(Gic_sh_mask + reg) |= mask;
  else
    *gic_mem<l4_uint32_t>(Gic_sh_mask + reg) |= mask;

  l4_umword_t pending = mask;
  int irq = reg * 8;

  // notify interrupt sources where necessary
  for (int i = 0; mask && i < (8 << size); ++i)
    {
      if ((mask & 1) && _sources[irq + i])
        _sources[irq + i]->eoi();
      mask >>= 1;
    }

  if (size == 3)
    pending &= *gic_mem<l4_uint64_t>(Gic_sh_pend + reg);
  else
    pending &= *gic_mem<l4_uint32_t>(Gic_sh_pend + reg);

  // reinject any interrupts that are still pending
  for (int i = 0; pending && i < (8 << size); ++i)
    {
      if (pending & 1)
        _irq_array[irq + i]->inject();
      pending >>= 1;
    }
}

void
Dist::setup_source(unsigned irq)
{
  assert(irq < Num_irqs);

  auto vp = *gic_mem<l4_uint32_t>(irq_to_mapreg(irq));
  if (!(vp & 0x1f))
    {
      _irq_array[irq].reset();
      return;
    }

  //TODO cpu
  auto pin = *gic_mem<Gic_pin_reg>(irq_to_pinreg(irq));

  trace.printf("GIC irq 0x%x: setting source for CPU %d to pin 0x%lx\n",
               irq, 0, pin.raw);

  // only int pins at the moment
  if (pin.pin() && pin.map() < 6)
    _irq_array[irq] = cxx::make_unique<Vmm::Irq_sink>(_core_ic->get_ic(0).get(),
                                                      pin.map() + 2);
   else
     _irq_array[irq].reset();
}

void
Dist::show_state(FILE *f)
{
  fprintf(f, " Interrupts available: %d\n", Num_irqs);

  for (unsigned i = 0; i < Num_irqs; ++i)
    {
      if (_irq_array[i])
        fprintf(f, " Int %d => core IC %u  %s/%s\n",
                i, gic_mem<Gic_pin_reg>(Gic_sh_pin + i * 4)->map() + 2,
                irq_mask()[i] ? "on" : "off",
                irq_pending()[i] ? "pending" : "low");
    }
}

namespace {

struct F : Vdev::Factory
{
  cxx::Ref_ptr<Vdev::Device> create(Vmm::Guest *vmm,
                                    Vmm::Virt_bus *,
                                    Vdev::Dt_node const &node)
  {
    l4_uint64_t size;

    int res = node.get_reg_val(0, nullptr, &size);
    if (res < 0)
      {
        Err().printf("Failed to read 'reg' from node %s: %s\n",
                     node.get_name(), node.strerror(res));
        throw L4::Runtime_error(-L4_EINVAL);
      }

    auto g = Vdev::make_device<Dist>(vmm->core_ic().get());
    vmm->register_mmio_device(g, node);
    return g;
  }

};

static F f;
static Vdev::Device_type t = { "mti,gic", nullptr, &f };

}

} // namespace
