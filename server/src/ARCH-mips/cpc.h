/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include "debug.h"
#include "mmio_device.h"
#include "cpu_dev_array.h"

namespace Vdev {

class Mips_cpc :  public Vmm::Mmio_device_t<Mips_cpc>
{
private:
  enum { Max_cpus = Vmm::Cpu_dev_array::Max_cpus };
  enum Cpc_local_registers
  {
    Cpc_cl_cmd_reg = 0x0,
    Cpc_cl_stat_conf_reg = 0x8
  };

  enum Cpc_commands
  {
    Cpc_cmd_clock_off = 1,
    Cpc_cmd_pwr_down = 2,
    Cpc_cmd_pwr_up = 3,
    Cpc_cmd_reset = 4
  };

public:
  enum Memmap
  {
    Cpc_size = 0x6000,
    Core_local_base = 0x2000,
    Core_other_base = 0x4000,
    Control_block_size = 0x2000
  };

  void register_cpus(cxx::Ref_ptr<Vmm::Cpu_dev_array> cpus)
  { _cpus = cpus; }

  void set_bev_base(l4_umword_t value)
  { _bev_base = value; }

  l4_umword_t bev_base() const
  { return _bev_base; }

  l4_umword_t read(unsigned reg, char size, unsigned cpuid);
  void write(unsigned reg, char size, l4_umword_t value, unsigned cpuid);

  l4_umword_t cm_read_core(unsigned reg, unsigned cpuid, bool other)
  {
    if (cpuid >= Max_cpus || !_cpus->vcpu_exists(cpuid))
      return 0;

    if (other)
      {
        cpuid = _cpus->cpu(cpuid)->core_other();
        if (cpuid >= Max_cpus || !_cpus->vcpu_exists(cpuid))
          {
            Dbg(Dbg::Cpu, Dbg::Info, "CMloc").printf(
                "CM reading from uninitialised core %d ignored.\n", cpuid);
            return 0;
          }
      }

    Dbg(Dbg::Cpu, Dbg::Trace, "CMloc").printf(
        "core %d: reading CM @ 0x%x\n", cpuid, reg);

    return _cpus->cpu(cpuid)->read_cm_reg(reg);
  }

  void cm_write_core(unsigned reg, l4_umword_t value, unsigned cpuid,
                     bool other)
  {
    if (cpuid >= Max_cpus || !_cpus->vcpu_exists(cpuid))
      return;

    if (other)
      {
        cpuid = _cpus->cpu(cpuid)->core_other();
        if (cpuid >= Max_cpus || !_cpus->vcpu_exists(cpuid))
          {
            Dbg(Dbg::Cpu, Dbg::Info, "CMloc").printf(
                "CM writing to uninitialised core %d ignored.\n", cpuid);
            return;
          }
      }

    Dbg(Dbg::Cpu, Dbg::Trace, "CMloc").printf(
        "core %d: writing CM 0x%lx @ 0x%x.\n", cpuid, value, reg);

    _cpus->cpu(cpuid)->write_cm_reg(reg, value);
  }

  /// Return the maximum CPU id in use.
  unsigned max_cpuid() const
  { return _cpus->max_cpuid(); }

private:
  l4_umword_t cpc_read_core(unsigned reg, unsigned cpuid);
  void cpc_write_core(unsigned reg, l4_umword_t value, unsigned cpuid);

  l4_umword_t _bev_base;
  cxx::Ref_ptr<Vmm::Cpu_dev_array> _cpus;
};

}
