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
#include "vcpu_array_t.h"

namespace Vmm {

/**
 * MIPS virtual CPU device.
 *
 * Also keeps the state of the CPU-local fields of the CM that
 * are relevant for SMP and provides access functions to manipulate
 * the CM local registers for the given CPU.
 */
class Vcpu_dev : public Vdev::Device
{
  enum { Default_procid = 0x00010000 };

  enum Cm_local_registers
  {
    Cm_loc_coh_en = 0x08,
    Cm_loc_config = 0x10,
    Cm_loc_other = 0x18,
    Cm_loc_reset_base = 0x20,
    Cm_loc_id = 0x28,
    Cm_loc_reset_ext_base = 0x30
  };

  // Mask of valid bits for various CM registers
  enum Cm_register_masks
  {
    Cm_loc_other_mask = 0x3f,
    Cm_loc_reset_base_mask = ~0xffcUL,
    Cm_loc_reset_base_addr_mask = ~0xfffUL,
    Cm_loc_reset_ext_base_mask = 0xcff000ff
  };

    enum Sequencer_state
  {
    Seq_pwr_down = 0x00,
    Seq_reset = 0x04,
    Seq_non_coherent = 0x06,
    Seq_coherent = 0x07,
  };

public:
  struct Local_status_reg
  {
    l4_uint32_t raw;
    CXX_BITFIELD_MEMBER(23, 23, pwrup_event, raw);
    CXX_BITFIELD_MEMBER(19, 22, seq_state, raw);
    CXX_BITFIELD_MEMBER(17, 17, clkgat_impl, raw);
    CXX_BITFIELD_MEMBER(16, 16, pwrdn_impl, raw);
    CXX_BITFIELD_MEMBER(15, 15, jtag_probe, raw);
    CXX_BITFIELD_MEMBER(14, 14, ci_pwrup, raw);
    CXX_BITFIELD_MEMBER(13, 13, ci_vddok, raw);
    CXX_BITFIELD_MEMBER(12, 12, ci_rail_stable, raw);
    CXX_BITFIELD_MEMBER(11, 11, coh_en, raw);
    CXX_BITFIELD_MEMBER(10, 10, lpack, raw);
    CXX_BITFIELD_MEMBER(8, 9, pwup_policy, raw);
    CXX_BITFIELD_MEMBER(7, 7, reset_hold, raw);
    CXX_BITFIELD_MEMBER(4, 4, io_trffc_en, raw);
    CXX_BITFIELD_MEMBER(0, 3, cmd, raw);
  };


  Vcpu_dev(unsigned id, l4_addr_t vcpu_baseaddr, unsigned phys_id)
  : _vcpu(Cpu((l4_vcpu_state_t *) vcpu_baseaddr)),
    _phys_cpu_id(phys_id),
    _core_other(0)
  {
    _vcpu.set_vcpu_id(id);
    _vcpu.set_proc_id(Default_procid);
    _vcpu.alloc_fpu_state();

    _status.raw = 0;
    _status.seq_state() = Seq_non_coherent;
  }

  void init_device(Vdev::Device_lookup const *, Vdev::Dt_node const &,
                   Vmm::Guest *, Vmm::Virt_bus *) override
  {}

  void set_proc_type(char const *compatible);

  Cpu vcpu() const
  { return _vcpu; }

  unsigned core_other() const
  { return _core_other; }

  l4_uint32_t cpc_status() const
  { return _status.raw; }

  void set_last_command(unsigned cmd)
  { _status.cmd() = cmd; }

  unsigned sched_cpu() const
  { return _phys_cpu_id; }

  l4_umword_t read_cm_reg(unsigned reg)
  {
    switch(reg)
    {
    case Cm_loc_coh_en: return _status.coh_en();
    case Cm_loc_config: return 0; // one VP per core
    case Cm_loc_other: return _core_other << 8;
    case Cm_loc_reset_base: return _reset_base;
    case Cm_loc_id: return _vcpu.get_vcpu_id();
    case Cm_loc_reset_ext_base: return _ext_reset_base;
    }

    return 0;
  }

  void write_cm_reg(unsigned reg, l4_umword_t value)
  {
    switch(reg)
      {
      case Cm_loc_coh_en:
        _status.coh_en() = value & 1;
        break;
      case Cm_loc_other:
        _core_other = (value >> 8) & Cm_loc_other_mask;
        break;
      case Cm_loc_reset_base:
        _reset_base = value & Cm_loc_reset_base_mask;
        break;
      case Cm_loc_reset_ext_base:
        _ext_reset_base = value & Cm_loc_reset_ext_base_mask;
        break;
      }
  }

  void set_coherent()
  {
    _status.seq_state() = Seq_coherent;
    _status.coh_en() = 1;
  }

  void start_vcpu(l4_addr_t bev_base);
  void stop_vcpu();

private:
  Cpu _vcpu;
  /// physical CPU to run on (offset into scheduling mask)
  unsigned _phys_cpu_id;
  /// CPC state: local status register
  Local_status_reg _status;
  /// CM state: reset address register
  l4_umword_t _reset_base;
  /// CM state: extension to reset address register
  l4_umword_t _ext_reset_base;
  /// CM/CPC state: selected other core.
  /// Note that starting with CM3, CM selects the other CPU for CM _and_ CPC.
  unsigned char _core_other;
};

/**
 * MIPS CPU array implementing a virtual cluster power controller.
 *
 * Multiple VCPUs are implemented each as a separate core with a
 * single VP. The VPs are non-continuously numbered. With the maximum
 * supported number of VPs being reported as 1, this results in each
 * VP having the same ID as the core.
 *
 * The state sequencer of the CPC is highly simplified, supporting only
 * the states "powered down", "non coherent" and "coherent".
 */
class Vcpu_array
: public Vcpu_array_t<Vcpu_dev, 32>,
  public Mmio_device_t<Vcpu_array>
{
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

  Vcpu_array()
  {
    _cpus[0]->set_coherent();
  }

  void show_state_registers(FILE *f);

  void set_bev_base(l4_umword_t value)
  { _bev_base = value; }

  l4_umword_t bev_base() const
  { return _bev_base; }

  l4_umword_t read(unsigned reg, char size, unsigned cpuid);
  void write(unsigned reg, char size, l4_umword_t value, unsigned cpuid);

  l4_umword_t cm_read_core(unsigned reg, unsigned cpuid, bool other)
  {
    if (cpuid >= Max_cpus || !_cpus[cpuid])
      return 0;

    if (other)
      {
        cpuid = _cpus[cpuid]->core_other();
        if (cpuid >= Max_cpus || !_cpus[cpuid])
          {
            Dbg(Dbg::Cpu, Dbg::Info, "CMloc").printf(
                "CM reading from uninitialised core %d ignored.\n", cpuid);
            return 0;
          }
      }

    Dbg(Dbg::Cpu, Dbg::Trace, "CMloc").printf(
        "core %d: reading CM @ 0x%x\n", cpuid, reg);

    return _cpus[cpuid]->read_cm_reg(reg);
  }

  void cm_write_core(unsigned reg, l4_umword_t value, unsigned cpuid,
                     bool other)
  {
    if (cpuid >= Max_cpus || !_cpus[cpuid])
      return;

    if (other)
      {
        cpuid = _cpus[cpuid]->core_other();
        if (cpuid >= Max_cpus || !_cpus[cpuid])
          {
            Dbg(Dbg::Cpu, Dbg::Info, "CMloc").printf(
                "CM writing to uninitialised core %d ignored.\n", cpuid);
            return;
          }
      }

    Dbg(Dbg::Cpu, Dbg::Trace, "CMloc").printf(
        "core %d: writing CM 0x%lx @ 0x%x.\n", cpuid, value, reg);

    _cpus[cpuid]->write_cm_reg(reg, value);
  }

private:
  l4_umword_t cpc_read_core(unsigned reg, unsigned cpuid);
  void cpc_write_core(unsigned reg, l4_umword_t value, unsigned cpuid);

  l4_umword_t _bev_base;
};

} // namespace
