/*
 * Copyright (C) 2015 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <mutex>

#include <l4/cxx/bitmap>
#include <l4/cxx/unique_ptr>
#include <l4/re/dataspace>
#include <l4/re/rm>
#include <l4/re/util/cap_alloc>

#include "irq.h"
#include "core_ic.h"
#include "device_tree.h"
#include "mmio_device.h"

namespace Gic {

class Dist
: public Vmm::Read_mapped_mmio_device_t<Dist, char>,
  public Ic
{
  enum Config
  {
    Num_irqs = 128, // maximum irq supported by Linux 3.19
    Cfg_words = Num_irqs >> 5, // 32 irq config bits per word
    Num_vpes = 32  // number of VPEs the GIC can handle
  };

  // The P5600 spec says there is a maximum of 256 irqs but the
  // data structures can accomodate up to 512. Only then the system breaks.
  static_assert(Num_irqs <= 512, "Maximum supported irqs is 512");
  static_assert(Num_irqs % 8 == 0, "Number of IRQs must be a multipe of 8");

  enum Mips_gic_registers
  {
    Gic_shared_base = 0,
    Gic_shared_size = 32 * 1024,
    Gic_core_local_base = 0x8000,
    Gic_core_other_base = 0xc000,
    Gic_local_size = 16 * 1024,
    Gic_user_visible_base = 0x16000,
    Gic_user_size = 64 * 1024,

    Gic_sh_config = 0x0,
    Gic_sh_counter = 0x10,
    Gic_sh_counter_lo = 0x10,
    Gic_sh_counter_hi = 0x14,
    Gic_sh_revision = 0x20,
    Gic_sh_int_avail = 0x28,
    Gic_sh_gid_config = 0x80,
    Gic_sh_pol = 0x100,
    Gic_sh_trig = 0x180,
    Gic_sh_dual = 0x200,
    Gic_sh_wedge = 0x280,
    Gic_sh_rmask = 0x300,
    Gic_sh_smask = 0x380,
    Gic_sh_mask = 0x400,
    Gic_sh_pend = 0x480,
    Gic_sh_pin = 0x500,
    Gic_sh_map = 0x2000,

    Gic_loc_other_addr = 0x80,
    Gic_loc_ident = 0x88,
  };

  struct Gic_config_reg
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER(31, 31, vzp, raw);
    CXX_BITFIELD_MEMBER(30, 30, vze, raw);
    CXX_BITFIELD_MEMBER(29, 29, irc, raw);
    CXX_BITFIELD_MEMBER(28, 28, countstop, raw);
    CXX_BITFIELD_MEMBER(24, 27, countbits, raw);
    CXX_BITFIELD_MEMBER(16, 23, numint, raw);
    CXX_BITFIELD_MEMBER(8, 15, irgid, raw);
    CXX_BITFIELD_MEMBER(0, 6, pvps, raw);
  };

  struct Gic_pin_reg
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER(31, 31, pin, raw);
    CXX_BITFIELD_MEMBER(30, 30, nmi, raw);
    CXX_BITFIELD_MEMBER(8, 15, gid, raw);
    CXX_BITFIELD_MEMBER(0, 5, map, raw);
  };

  struct Gic_wedge_reg
  {
    l4_umword_t raw;
    CXX_BITFIELD_MEMBER(31, 31, rw, raw);
    CXX_BITFIELD_MEMBER(0, 7, irq, raw);

    explicit Gic_wedge_reg(l4_umword_t value) : raw(value) {}
  };

  struct Cpu_info
  {
    unsigned other_cpu = 0;
  };

public:
  Dist(Mips_core_ic *core_ic);

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &) override
  {}

  l4_umword_t read(unsigned reg, char size, unsigned cpu_id);
  void write(unsigned reg, char size, l4_umword_t value, unsigned cpu_id);

  void set(unsigned irq) override
  {
    assert(irq < Num_irqs);
    std::lock_guard<std::mutex> lock(_lock);

    if (!_irq_array[irq])
      return;

    irq_pending().set_bit(irq);

    if (irq_mask()[irq])
      _irq_array[irq]->inject();
  }

  void clear(unsigned irq) override
  {
    assert(irq < Num_irqs);
    std::lock_guard<std::mutex> lock(_lock);

    if (!_irq_array[irq])
      return;

    irq_pending().clear_bit(irq);

    if (irq_mask()[irq])
      _irq_array[irq]->ack();
  }

  void bind_irq_source(unsigned irq, cxx::Ref_ptr<Irq_source> const &src) override
  {
    assert(irq < Num_irqs);

    if (_sources[irq])
      throw L4::Runtime_error(-L4_EEXIST);

    _sources[irq] = src;
  }

  cxx::Ref_ptr<Irq_source> get_irq_source(unsigned irq) const override
  { return _sources[irq]; }

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

  void reset_mask(unsigned reg, char size, l4_umword_t mask);
  void set_mask(unsigned reg, char size, l4_umword_t mask);
  void setup_source(unsigned irq);

  void show_state(FILE *);

private:
  /**
   * Return offset of map register for the given IRQ.
   *
   * Map registers spaced at 0x20 byte intervals.
   */
  unsigned irq_to_mapreg(unsigned irq) const
  { return Gic_sh_map + irq * 0x20; }

  unsigned mapreg_to_irq(unsigned offset) const
  { return (offset - Gic_sh_map) / 0x20; }

  cxx::Bitmap_base irq_mask() const
  { return cxx::Bitmap_base(gic_mem<void>(Gic_sh_mask)); }

  cxx::Bitmap_base irq_pending() const
  { return cxx::Bitmap_base(gic_mem<void>(Gic_sh_pend)); }

  /**
   * Return offset of pin register for the given IRQ.
   *
   * Pin registers spaced at 4 byte intervals.
   */
  unsigned irq_to_pinreg(unsigned irq) const
  { return Gic_sh_pin + irq * 4; }

  unsigned pinreg_to_irq(unsigned offset) const
  { return (offset - Gic_sh_pin) / 4; }

  template <typename T>
  T *gic_mem(unsigned offset) const
  { return reinterpret_cast<T *>(_mmio_region.get() + offset); }

  void gic_mem_set(unsigned offset, char size, l4_umword_t value) const
  {
    if (size == 3)
      *gic_mem<l4_uint64_t>(offset) = value;
    else
      *gic_mem<l4_uint32_t>(offset) = value;
  }

  l4_umword_t read_cpu(unsigned reg, char size, unsigned cpu_id);
  void write_cpu(unsigned reg, char size, l4_umword_t value,
                 unsigned cpu_id);

  Mips_core_ic *_core_ic;
  // array of IRQ connections towards core IC
  cxx::unique_ptr<Vmm::Irq_sink> _irq_array[Num_irqs];
  // registered device callbacks for configuration and eoi
  cxx::Ref_ptr<Irq_source> _sources[Num_irqs];
  Cpu_info _vcpu_info[Num_vpes];
  std::mutex _lock;
};

} // namespace
