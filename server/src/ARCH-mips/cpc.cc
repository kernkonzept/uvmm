/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "cpc.h"

namespace Vdev {

static Dbg warn(Dbg::Cpu, Dbg::Warn, "CPC");
static Dbg info(Dbg::Cpu, Dbg::Info, "CPC");
static Dbg trace(Dbg::Cpu, Dbg::Trace, "CPC");

l4_umword_t
Mips_cpc::read(unsigned reg, char, unsigned cpuid)
{
  trace.printf("reading CPC @ 0x%x\n", reg);

  if (reg >= Core_local_base && reg < Core_local_base + Control_block_size)
    return cpc_read_core(reg - Core_local_base, cpuid);

  if (reg >= Core_other_base && reg < Core_other_base + Control_block_size)
    {
      if ((cpuid >= Max_cpus) || !_cpus->vcpu_exists(cpuid))
        {
          info.printf("read on unknown other core %d. Ignored.\n", cpuid);
          return 0;
        }

      return cpc_read_core(reg - Core_other_base, _cpus->cpu(cpuid)->core_other());
    }

  info.printf("reading unknown register @ 0x%x ignored.\n", reg);
  return 0;
}

void
Mips_cpc::write(unsigned reg, char, l4_umword_t value, unsigned cpuid)
{
  trace.printf("writing CPC 0x%lx @ 0x%x\n", value, reg);

  if (reg >= Core_local_base && reg < Core_local_base + Control_block_size)
    cpc_write_core(reg - Core_local_base, value, cpuid);
  else if (reg >= Core_other_base && reg < Core_other_base + Control_block_size)
    {
      if ((cpuid < Max_cpus) && _cpus->vcpu_exists(cpuid))
        cpc_write_core(reg - Core_other_base, value, _cpus->cpu(cpuid)->core_other());
      else
        info.printf("read on unknown other core %d. Ignored.\n", cpuid);
    }
  else
    info.printf("writing unknown register 0x%lx @ 0x%x ignored.\n", value, reg);
}

l4_umword_t
Mips_cpc::cpc_read_core(unsigned reg, unsigned cpuid)
{
  if (cpuid >= Max_cpus || !_cpus->vcpu_exists(cpuid))
    {
      info.printf("CPC reading from uninitialised core %d ignored.\n", cpuid);
      return 0;
    }

  trace.printf("core %d: reading CPC @ 0x%x\n", cpuid, reg);

  switch (reg)
    {
    case Cpc_cl_stat_conf_reg:
      return _cpus->cpu(cpuid)->cpc_status();
    default:
      info.printf("core %d: reading CPC @ 0x%x ignored.\n", cpuid, reg);
    }

  return 0;
}

void
Mips_cpc::cpc_write_core(unsigned reg, l4_umword_t value, unsigned cpuid)
{
  if (cpuid >= Max_cpus || !_cpus->vcpu_exists(cpuid))
    {
      info.printf("CPC writing to uninitialised core %d ignored.\n", cpuid);
      return;
    }

  trace.printf("core %d: writing CPC 0x%lx @ 0x%x\n", cpuid, value, reg);

  switch (reg)
    {
    case Cpc_cl_cmd_reg:
      {
        unsigned cmd = value & 0x7;
        _cpus->cpu(cpuid)->set_last_command(cmd);

        switch (cmd)
          {
          case Cpc_cmd_pwr_down:
            _cpus->cpu(cpuid)->stop_vcpu();
            break;
          case Cpc_cmd_pwr_up:
          case Cpc_cmd_reset:
            _cpus->cpu(cpuid)->start_vcpu(_bev_base);
            break;
          }
        break;
      }
    default:
      info.printf("core %d: writing 0x%lx @ 0x%x ignored.\n",
                  cpuid, value, reg);
    }
}



}
