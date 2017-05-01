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
: gicd_info(Dbg::Irq, Dbg::Info, "GICD"), ctlr(0), tnlines(tnlines), cpus(cpus),
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

            gicd_info.printf("read (%x:%zd) val=%08x\n", reg, g - reg_group, v);
            return v;
          }
      return 0;
    }

  if (r >= 0xf10 && r < 0xf40)
    return _cpu[cpu_id].read_sgi_pend(((r - 0xf00) / 4) & 3);

  return 0;
}


static bool atomic_set_bits(uint32_t *addr, uint32_t mask)
{
  l4_uint32_t old = __atomic_load_n(addr, __ATOMIC_ACQUIRE);
  l4_uint32_t nv;

  do
    {
      nv = old | mask;
      if (nv == old)
        return false;
    }
  while (!__atomic_compare_exchange_n(addr, &old, nv, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));

  return true;
}

static void atomic_clear_bits(uint32_t *addr, uint32_t bits)
{
  l4_uint32_t old = __atomic_load_n(addr, __ATOMIC_ACQUIRE);
  l4_uint32_t mask = ~bits;
  l4_uint32_t nv;
  do
    {
      nv = old & mask;
      if (nv == old)
        return;
    }
  while (!__atomic_compare_exchange_n(addr, &old, nv, true,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
}

bool Gic::Cpu::set_sgi(unsigned irq)
{
  unsigned reg = irq / 4;
  unsigned field_off = irq % 4;
  l4_uint32_t bit = 1UL << (field_off * 8 + vmm_current_cpu_id);

  return atomic_set_bits(&_sgi_pend[reg], bit);
}

void Gic::Cpu::clear_sgi(unsigned irq, unsigned src)
{
  unsigned reg = irq / 4;
  unsigned field_off = irq % 4;
  l4_uint32_t bit = (1UL << (field_off * 8 + src));

  atomic_clear_bits(&_sgi_pend[reg], bit);
}

void
Gic::Cpu::dump_sgis() const
{
  for (auto const &pending : _sgi_pend)
    printf("%02x ", pending);
  puts("");
}

void
Gic::Cpu::ipi(unsigned irq)
{
  if (set_sgi(irq))
    notify();
}

void
Gic::Dist::sgir_write(l4_uint32_t value)
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
  for (unsigned cpu = 0; cpu < cpus && targets; ++cpu, targets >>= 1)
    if (targets & 1)
      {
        if (cpu != vmm_current_cpu_id)
          _cpu[cpu].ipi(irq);
        else
          inject_local(irq, vmm_current_cpu_id);
      }
}

void Gic::Dist::notify_cpus(unsigned targets) const
{
  for (unsigned cpu = 0; cpu < cpus && targets; ++cpu, targets >>= 1)
    if ((targets & 1) && (cpu != vmm_current_cpu_id))
      _cpu[cpu].notify();
}

void
Gic::Cpu::handle_ipis()
{
  unsigned irq_idx = 0;

  for (auto pending : _sgi_pend)
    {
      for (unsigned irq_num = irq_idx; pending; pending >>= 8, ++irq_num)
        {
          char cpu_bits = pending & 0xff;
          if (!cpu_bits)
            continue;

          // inject one IPI, if another CPU posted the same IPI we keep it
          // pending
          unsigned src = __builtin_ffs((int)cpu_bits) - 1;
          auto irq = local_irq(irq_num);

          // set irq pending and try to inject
          if (irq.pending(true))
            {
              if (!inject(irq, irq_num, src))
                {
                  Dbg(Dbg::Cpu, Dbg::Info, "IPI")
                    .printf("Cpu%d: Failed to inject irq %d\n",
                            vmm_current_cpu_id, irq_num);
                  return;
                }
              clear_sgi(irq_num, src);
            }
          else
            {
              Dbg(Dbg::Cpu, Dbg::Info, "IPI")
                .printf("Cpu%d: Failed to set irq %d to pending,"
                        " current state: %s (%08x)\n",
                        vmm_current_cpu_id, irq_num,
                        irq.pending() ? "pending" : "not pending", irq.state());
            }
        }
      // sizeof(char) per irq in pending
      irq_idx += sizeof(pending);
    }
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
    {
      Dbg(Dbg::Mmio, Dbg::Warn, "Dist")
        .printf("Ignoring write access to %x, %x\n", r, value);
      return;
    }

  if (r < 0xf00)
    {
      reg &= (~0UL) << size;
      for (Reg_group_info const *g = &reg_group[Num_reg_group - 1];
           g != reg_group;
           --g)
        if (reg >= g->base)
          {
            gicd_info.printf("write (%x:%zd) val = %08x\n",
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

  if (r == SGIR)
    sgir_write(value);
  else if (r >= 0xf10 && r < 0xf20)
    _cpu[cpu_id].write_clear_sgi_pend((r - 0xf10) / 4, value);
  else if (r >= 0xf20 && r < 0xf40)
    _cpu[cpu_id].write_set_sgi_pend((r - 0xf20) / 4, value);
  else
    Dbg(Dbg::Mmio, Dbg::Warn, "Dist")
      .printf("Ignoring write access to %x, %x\n", r, value);
}

void Gic::Irq_array::Pending::show_header(FILE *f)
{ fprintf(f, "Irq     raw pen act ena src tar pri con grp\n"); }

void Gic::Irq_array::Pending::show(FILE *f, int irq) const
{
  fprintf(f, "%3d %x  %c   %c   %c  %3d %3d %3d %3d %3d\n",
          irq, _state,
          pending() ? 'y' : 'n',
          active()  ? 'y' : 'n',
          enabled() ? 'y' : 'n',
          (int)src(),
          (int)target(),
          (int)prio(),
          (int)config(),
          (int)group());
}

void
Gic::Cpu::show(FILE *f, unsigned cpu)
{
  fprintf(f, "#\n# Cpu %d\n#\n", cpu);
  Gic::Irq_array::Const_irq::show_header(f);
  for (unsigned i = 0; i < Num_local; ++i)
    if (_local_irq[i].enabled())
      _local_irq[i].show(f, i);
}

void
Gic::Dist::show(FILE *f) const
{
  for (unsigned i = 0; i < cpus; ++i)
    _cpu[i].show(f, i);

  fprintf(f, "#\n# Spis\n#\n");
  Gic::Irq_array::Const_irq::show_header(f);
  for (unsigned i = 0; i < tnlines * 32; ++i)
    if (_spis[i].enabled())
      _spis[i].show(f, i + Cpu::Num_local);
}
