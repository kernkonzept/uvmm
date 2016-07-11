/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/unique_ptr>
#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/util/cap_alloc>

#include "irq.h"
#include "core_ic.h"
#include "device_tree.h"
#include "arch_mmio_device.h"
#include "vcpu.h"

namespace Gic {

class Dist
: public Vmm::Read_mapped_mmio_device_t<Dist, l4_uint32_t>,
  public Ic
{
  enum Config
  {
    Num_irqs = 128, // maximum irq supported by Linux 3.19
    Cfg_words = Num_irqs >> 5 // 32 irq config bits per word
  };

  // The P5600 spec says there is a maximum of 256 irqs but the
  // data structures can accomodate up to 512. Only then the system breaks.
  static_assert(Num_irqs <= 512, "Maximum supported irqs is 512");

  enum Mips_gic_registers
  {
    Gic_shared_base = 0,
    Gic_shared_size = 32 * 1024,
    Gic_core_local_base = 0x8000,
    Gic_core_other_base = 0x12000,
    Gic_local_size = 16 * 1024,
    Gic_user_visible_base = 0x16000,
    Gic_user_size = 64 * 1024,

    Gic_sh_config = 0x0,
    Gic_sh_counter_lo = 0x4,
    Gic_sh_counter_hi = 0x5,
    Gic_sh_revision = 0x8,
    Gic_sh_int_avail = 0x9,
    Gic_sh_gid_config = 0x20,
    Gic_sh_pol = 0x40,
    Gic_sh_trig = 0x60,
    Gic_sh_dual = 0x80,
    Gic_sh_wedge = 0xa0,
    Gic_sh_rmask = 0xc0,
    Gic_sh_smask = 0xe0,
    Gic_sh_mask = 0x100,
    Gic_sh_pend = 0x120,
    Gic_sh_pin = 0x140,
    Gic_sh_map = 0x800,
    Gic_vb_dint_send = 0x1800
  };

public:
  Dist(l4_size_t size);

  void init_device(Vdev::Device_lookup const *,
                   Vdev::Dt_node const &) override
  {}

  void set_core_ic(Mips_core_ic *core_ic)
  { _core_ic = core_ic; }

  l4_uint32_t read(unsigned reg, char size, unsigned cpu_id);
  void write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id);

  void set(unsigned irq) override
  {
    assert(irq < Num_irqs);

    if (!_irq_array[irq])
      return;

    unsigned reg = irq >> 5;
    unsigned mask = 1UL << (irq & 0x1f);

    _mmio_region.get()[Gic_sh_pend + reg] |= mask;

    if (_mmio_region.get()[Gic_sh_mask + reg] & mask)
      _irq_array[irq]->inject();
  }

  void clear(unsigned irq) override
  {
    assert(irq < Num_irqs);

    if (!_irq_array[irq])
      return;

    unsigned reg = irq >> 5;
    unsigned mask = 1UL << (irq & 0x1f);

    _mmio_region.get()[Gic_sh_pend + reg] &= ~mask;

    if (_mmio_region.get()[Gic_sh_mask + reg] & mask)
      _irq_array[irq]->ack();
  }

  void bind_irq_source(unsigned irq, cxx::Ref_ptr<Irq_source> src) override
  {
    assert(irq < Num_irqs);

    _sources[irq] = src;
  }

  int dt_get_num_interrupts(Vdev::Dt_node const &node) override
  {
    int size;
    if (!node.get_prop<fdt32_t>("interrupts", &size))
      return 0;

    return size / 3;
  }

  unsigned dt_get_interrupt(Vdev::Dt_node const &node, int irq) override
  {
    auto *prop = node.check_prop<fdt32_t>("interrupts", 3 * (irq + 1));

    return fdt32_to_cpu(prop[3 * irq + 1]);
  }

  void reset_mask(unsigned reg, l4_uint32_t mask);
  void set_mask(unsigned reg, l4_uint32_t mask);
  void setup_source(unsigned irq, l4_uint32_t cpu, l4_uint32_t pin);

  void show_state(FILE *);

private:
  l4_uint32_t read_cpu(unsigned reg, unsigned cpu_id);
  void write_cpu(unsigned reg, l4_uint32_t value, unsigned cpu_id);

  unsigned _other_cpu = 1;

  Mips_core_ic *_core_ic;
  // array of IRQ connections towards core IC
  cxx::unique_ptr<Vmm::Irq_sink> _irq_array[Num_irqs];
  // registered device callbacks for configuration and eoi
  cxx::Ref_ptr<Irq_source> _sources[Num_irqs];

};


} // namespace
