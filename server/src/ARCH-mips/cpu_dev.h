/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include "generic_cpu_dev.h"

#include <cstdio>

namespace Vmm {

class Cpu_dev : public Generic_cpu_dev
{
public:
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

  struct Local_status_reg
  {
    l4_uint32_t raw;
    Local_status_reg() = default;
    explicit Local_status_reg(l4_uint32_t raw) : raw(raw) {}

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

  Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *node);

  /**
   * Translate a device tree "reg" value to an internally usable CPU id.
   *
   * For most architectures this is NOP, but some archictures like ARM
   * might encode topology information into this value, which needs to
   * be translated.
   */
  static unsigned dtid_to_cpuid(l4_int32_t prop_val)
  { return prop_val; }

  void show_state_registers(FILE *f);
  unsigned core_other() const
  { return _core_other; }

  l4_uint32_t cpc_status() const
  { return _status.raw; }

  void set_last_command(unsigned cmd)
  { _status.cmd() = cmd; }

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

  void reset() override;

private:
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

}
