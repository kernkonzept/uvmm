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

namespace {

Dbg dbg(Dbg::Info, "GIC");

} // namespace

namespace Gic {


Dist::Dist(l4_size_t size)
: Read_mapped_mmio_device_t(size)
{
  static_assert(L4_PAGESIZE <= 16 * 1024, "Maximum supported page size is 16k");

  // set up shared section
  l4_uint32_t *sh = _mmio_region.get();
  sh[Gic_sh_config] = ((Num_irqs >> 3) - 1) << 16;
  sh[Gic_sh_revision] = 4 << 8; // 4.0, as reported by Baikal board

  memset(sh + Gic_sh_int_avail, 0xff, Num_irqs >> 3);
  memset(sh + Gic_sh_pend, 0, Num_irqs >> 3);
}

l4_uint32_t
Dist::read(unsigned reg, char size, unsigned cpu_id)
{
  if (reg >= Gic_core_other_base && reg < Gic_user_visible_base)
    return read_cpu(reg - Gic_core_other_base, _other_cpu);
  if (reg < Gic_shared_base + Gic_shared_size)
    return _mmio_region.get()[reg >> 2];
  if (reg >= Gic_core_local_base && reg < Gic_core_other_base)
    return read_cpu(reg - Gic_core_local_base, cpu_id);

  dbg.printf("Reading unknown register @ 0x%x (%d)\n", reg, size);
  return 0;
}

void
Dist::write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
{
  if (reg >= Gic_core_local_base && reg < Gic_core_other_base)
    return write_cpu(reg - Gic_core_local_base, value, cpu_id);
  if (reg >= Gic_core_other_base && reg < Gic_user_visible_base)
    return write_cpu(reg - Gic_core_other_base, value, _other_cpu);

  // write must be to shared section
  l4_uint32_t *sh = _mmio_region.get();
  reg >>= 2;

  if (reg >= Gic_sh_pol && reg < Gic_sh_wedge)
    {
      sh[reg] = value; // polarity, edge, dual configuration ignored
    }
  else if (reg >= Gic_sh_rmask && reg < Gic_sh_smask)
    {
      reset_mask(reg - Gic_sh_rmask, value);
    }
  else if (reg >= Gic_sh_smask && reg < Gic_sh_mask)
    {
      set_mask(reg - Gic_sh_smask, value);
    }
  else if (reg >= Gic_sh_pin && reg < Gic_sh_pin + Num_irqs)
    {
      sh[reg] = value;
      setup_source(reg - Gic_sh_pin, sh[reg - Gic_sh_pin + Gic_sh_map],
                   sh[reg]);
    }
  else if (reg >= Gic_sh_map && reg < Gic_sh_map + Num_irqs)
    {
      sh[reg] = value;
      setup_source(reg - Gic_sh_map, sh[reg],
                   sh[reg - Gic_sh_map + Gic_sh_pin]);
    }
  else if (reg == Gic_vb_dint_send)
    {
      sh[reg] = value;
    }
  else
    dbg.printf("Writing ignored 0x%x @ 0x%x (%d)\n", value, reg, size);
}

l4_uint32_t
Dist::read_cpu(unsigned reg, unsigned cpu_id)
{
  if (reg < Gic_local_size)
    return _mmio_region.get()[(reg + Gic_core_local_base) >> 2];

  dbg.printf("Local read from cpu %d ignored @ 0x%x\n",
             cpu_id, reg);
  return 0;
}

void
Dist::write_cpu(unsigned reg, l4_uint32_t value, unsigned cpu_id)
{
  dbg.printf("Local write to cpu %d ignored 0x%x @ 0x%x\n",
             cpu_id, value, reg);
}

void
Dist::reset_mask(unsigned reg, l4_uint32_t mask)
{
  l4_uint32_t *sh = _mmio_region.get();

  sh[Gic_sh_mask + reg] &= ~mask;

  l4_uint32_t pending = mask & sh[Gic_sh_pend + reg];
  int irq = reg * 32;

  while (pending)
    {
      if (pending & 1)
        _irq_array[irq]->ack();

      ++irq;
      pending >>= 1;
    }
}

void
Dist::set_mask(unsigned reg, l4_uint32_t mask)
{
  l4_uint32_t *sh = _mmio_region.get();

  sh[Gic_sh_mask + reg] |= mask;
  l4_uint32_t pending = mask;
  int irq = reg * 32;

  // clear interrupts, where necessary
  for (int i = 0; mask && i < 32; ++i)
    {
      if ((mask & 1) && _sources[irq + i])
        _sources[irq + i]->eoi();
      mask >>= 1;
    }

  pending &= sh[Gic_sh_pend + reg];

  // reinject any interrupts that are still pending
  for (int i = 0; pending && i < 32; ++i)
    {
      if (pending & 1)
        _irq_array[irq + i]->inject();
      pending >>= 1;
    }
}

void
Dist::setup_source(unsigned irq, l4_uint32_t cpu, l4_uint32_t pin)
{
  (void)cpu; // TODO

  // only int pins at the moment
  if (pin & (1 << 31) && (pin & 0x1f) < 6)
    _irq_array[irq] = cxx::make_unique<Vmm::Irq_sink>(_core_ic, (pin & 0x1f) + 2);
  else
    _irq_array[irq].reset();
}

void
Dist::show_state(FILE *f)
{
  l4_uint32_t *sh = _mmio_region.get();

  fprintf(f, " Interrupts available: %d\n", Num_irqs);

  for (unsigned i = 0; i < Num_irqs; ++i)
    {
      if (!_irq_array[i])
        continue;

      unsigned reg = i >> 5;
      l4_uint32_t mask = 1 << (i & 0x1f);

      fprintf(f, " Int %d => core IC %u  %s/%s\n",
              i, (sh[Gic_sh_pin + i] & 0x1f) + 2,
              (mask & sh[Gic_sh_mask + reg]) ? "on" : "off",
              (mask & sh[Gic_sh_pend + reg]) ? "pending" : "low");
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
    node.get_reg_val(0, nullptr, &size);

    auto g = Vdev::make_device<Dist>(size);
    g->set_core_ic(vmm->core_ic().get());
    vmm->register_mmio_device(g, node);
    return g;
  }

};

static F f;
static Vdev::Device_type t = { "mti,gic", nullptr, &f };

}

} // namespace
