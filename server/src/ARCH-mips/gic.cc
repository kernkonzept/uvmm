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
  if (reg >= Gic_core_local_base && reg < Gic_core_other_base)
    return write_cpu(reg - Gic_core_local_base, size, value, cpu_id);
  if (reg >= Gic_core_other_base && reg < Gic_user_visible_base)
    return write_cpu(reg - Gic_core_other_base, size, value, _other_cpu);

  // write must be to shared section
  if (reg >= Gic_sh_pol && reg < Gic_sh_wedge)
    {
      // polarity, edge, dual configuration ignored
      gic_mem_set(reg, size, value);
    }
  else if (reg >= Gic_sh_rmask && reg < Gic_sh_smask)
    {
      reset_mask(reg - Gic_sh_rmask, size, value);
    }
  else if (reg >= Gic_sh_smask && reg < Gic_sh_mask)
    {
      set_mask(reg - Gic_sh_smask, size, value);
    }
  else if (reg >= Gic_sh_pin && reg < Gic_sh_pin + Num_irqs)
    {
      gic_mem_set(reg, size, value);
      setup_source(pinreg_to_irq(reg));
    }
  else if (reg >= Gic_sh_map && reg < Gic_sh_map + Num_irqs)
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
  dbg.printf("Local read from cpu %d ignored @ 0x%x\n",
             cpu_id, reg);
  return 0;
}

void
Dist::write_cpu(unsigned reg, char, l4_umword_t value, unsigned cpu_id)
{
  dbg.printf("Local write to cpu %d ignored 0x%lx @ 0x%x\n",
             cpu_id, value, reg);
}

/** disable interrupts */
void
Dist::reset_mask(unsigned reg, char size, l4_umword_t mask)
{
  l4_umword_t pending;

  if (size == 3)
    {
      *gic_mem<l4_uint64_t>(Gic_sh_mask + reg) &= ~mask;
      pending = mask & *gic_mem<l4_uint64_t>(Gic_sh_pend + reg);
    }
  else
    {
      *gic_mem<l4_uint32_t>(Gic_sh_mask + reg) &= ~mask;
      pending = mask & *gic_mem<l4_uint32_t>(Gic_sh_pend + reg);
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
  if (size == 3)
    *gic_mem<l4_uint64_t>(Gic_sh_mask + reg) |= mask;
  else
    *gic_mem<l4_uint32_t>(Gic_sh_mask + reg) |= mask;

  l4_umword_t pending = mask;
  int irq = reg * 8;

  // notify interrupt sources where necessary
  for (int i = 0; mask && i < 8 * (1 << size); ++i)
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
  for (int i = 0; pending && i < 8 * (1 << size); ++i)
    {
      if (pending & 1)
        _irq_array[irq + i]->inject();
      pending >>= 1;
    }
}

void
Dist::setup_source(unsigned irq)
{
  auto vp = *gic_mem<l4_uint32_t>(irq_to_mapreg(irq));
  dbg.printf("IRQ %d setup source: for VP %d\n", irq, vp);
  if (!(vp & 0x1f))
    {
      _irq_array[irq].reset();
      return;
    }

  //TODO cpu
  auto pin = *gic_mem<Gic_pin_reg>(irq_to_pinreg(irq));

  dbg.printf("GIC irq 0x%x: setting source for CPU %d to pin 0x%lx\n",
             irq, 0, pin.raw);

  // only int pins at the moment
  if (pin.pin() && pin.map() < 6)
    _irq_array[irq] = cxx::make_unique<Vmm::Irq_sink>(_core_ic,
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
