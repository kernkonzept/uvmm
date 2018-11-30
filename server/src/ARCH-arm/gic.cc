/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#include "gic.h"

Gic::Dist::Reg_group_info const Gic::Dist::reg_group[10] =
{
    { 0x080,  3, 0x01 }, // group
    { 0x100,  3, 0x01 }, // enable set
    { 0x180,  3, 0x01 }, // enable clear
    { 0x200,  3, 0x01 }, // pending set
    { 0x280,  3, 0x01 }, // pending clear
    { 0x300,  3, 0x01 }, // active set
    { 0x380,  3, 0x01 }, // active clear
    { 0x400,  0, 0xff }, // priority
    { 0x800,  0, 0xff }, // target
    { 0xc00,  2, 0x03 }  // config
};

enum {
  Num_reg_group = sizeof(Gic::Dist::reg_group) / sizeof(Gic::Dist::reg_group[0])
};

Gic::Dist::Dist(unsigned tnlines, unsigned char cpus)
: gicd_info(Dbg::Gicd, "GICD"), ctlr(0), tnlines(tnlines), cpus(cpus),
  _active_grp0_cpus(0), _active_grp1_cpus(0),
  _spis(tnlines * 32)
{
  _cpu = cxx::unique_ptr<Cpu[]>(new Cpu[cpus]);
  for (unsigned i = 0; i < cpus; ++i)
    _cpu[i].setup(i, &_spis);
}

l4_uint32_t
Gic::Dist::read(unsigned reg, char size, unsigned cpu_id)
{
  unsigned r = reg & ~3;
  switch (r)
    {
    case CTLR: return ctlr;
    case TYPER: return tnlines | ((l4_uint32_t)cpus << 5);
    case IIDR: return 0x43b;
    default: break;
    }

  if (r < 0x080)
    return 0;

  if (r < 0xf00)
    {
      reg &= (~0UL) << size;
      for (Reg_group_info const *g = &reg_group[Num_reg_group - 1];
           g != reg_group;
           --g)
        if (reg >= g->base)
          {
            l4_uint32_t v = 0;
            int irq_s = (reg - g->base) << g->shift;
            int irq_e = irq_s + ((1 << size) << g->shift);
            unsigned rgroup = g - reg_group;
            l4_uint32_t mask = g->mask;

            if (irq_s < 32)
              {
                for (int i = irq_e - 1; i >= irq_s; --i)
                  {
                    v <<= (8 >> g->shift);
                    v |= irq_mmio_read(_cpu[cpu_id].local_irq(i),
                                      rgroup) & mask;
                  }
                return v;
              }

            irq_s -= 32;
            irq_e -= 32;

            for (int i = irq_e - 1; i >= irq_s; --i)
              {
                v <<= (8 >> g->shift);
                if (i < tnlines * 32)
                  v |= irq_mmio_read(spi(i), rgroup) & mask;
                else
                  break;
              }

            gicd_info.printf("read (%x:%d) val=%08x\n", reg, g - reg_group, v);
            return v;
          }
      return 0;
    }

  if (r >= 0xf10 && r < 0xf40)
    return _cpu[cpu_id].read_sgi_pend(((r - 0xf00) / 4) & 3);

  return 0;
}

void
Gic::Dist::write(unsigned reg, char size, l4_uint32_t value, unsigned cpu_id)
{
  unsigned r = reg & ~3;
  switch (r)
    {
    case CTLR: ctlr = value;
    default: break;
    };

  if (r < 0x080)
    return;

  if (r < 0xf00)
    {
      reg &= (~0UL) << size;
      for (Reg_group_info const *g = &reg_group[Num_reg_group - 1];
           g != reg_group;
           --g)
        if (reg >= g->base)
          {
            gicd_info.printf("write (%x:%d) val = %08x\n",
                             reg, g - reg_group, value);
            unsigned irq_s = (reg - g->base) << g->shift;
            unsigned irq_e = irq_s + ((1 << size) << g->shift);
            l4_uint32_t mask = g->mask;
            l4_uint32_t v = value;
            unsigned rgroup = g - reg_group;

            if (irq_s < 32)
              {
                if (irq_s < 16 && (rgroup == R_ispend || rgroup == R_icpend))
                  irq_s = 16; // RO for SGIs
                else if (rgroup == R_target)
                  return; // these are RO for local IRQs

                for (unsigned i = irq_s; i < irq_e; ++i)
                  {
                    irq_mmio_write(_cpu[cpu_id].local_irq(i),
                                   i, rgroup, v & mask);
                    v >>= (8 >> g->shift);
                  }
                return;
              }

            irq_s -= 32;
            irq_e -= 32;

            for (unsigned i = irq_s; i < irq_e; ++i)
              {
                if (i < tnlines * 32)
                  irq_mmio_write(spi(i), i + 32, g - reg_group, v & mask);
                else
                  return;

                v >>= (8 >> g->shift);
              }
            return;
          }
      return;
    }

  if (r >= 0xf10 && r < 0xf20)
    _cpu[cpu_id].write_clear_sgi_pend((r - 0xf10) / 4, value);
  else if (r >= 0xf20 && r < 0xf40)
    _cpu[cpu_id].write_set_sgi_pend((r - 0xf20) / 4, value);
}
