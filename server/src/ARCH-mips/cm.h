/*
 * Copyright (C) 2017 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cassert>

#include "mmio_device.h"
#include "vm_memmap.h"
#include "cpc.h"

namespace Vdev {

/**
 * Virtual Mips coherency manager.
 *
 * This device only implements the global registers of the CM and
 * only emulatates functionality necessary for SMP support.
 * Access to the CPU-local registers are forwarded to the
 * CPC.
 *
 * Each VCPU is reported as a separate core with exactly one VPE.
 */
class Coherency_manager : public Vmm::Mmio_device_t<Coherency_manager>
{
  enum Memmap
  {
    Base_address = 0x1fbf8000,
    Cm_size = 0x10000,
    Control_block_size = 0x2000,
    Core_local_base = 0x2000,
    Core_other_base = 0x4000
  };

  enum Global_control_block
  {
    Gcr_config = 0x0,
    Gcr_base = 0x8,
    Gcr_control = 0x10,
    Gcr_rev = 0x30,
    Gcr_gic_base = 0x80,
    Gcr_cpc_base = 0x88,
    Gcr_gic_status = 0xd0,
    Gcr_cpc_status = 0xf0,
    Gcr_sys_config2 = 0x150,
    Gcr_bev_base = 0x680
  };

public:
  struct Cpc_base_addr_reg
  {
    Cpc_base_addr_reg() = default;
    explicit Cpc_base_addr_reg(l4_umword_t value) : raw(value) {}

    l4_umword_t raw;

    CXX_BITFIELD_MEMBER(0, 0, enable, raw);
#ifdef __mips64
    CXX_BITFIELD_MEMBER_UNSHIFTED_RO(15, 47, base_addr, raw);
#else
    CXX_BITFIELD_MEMBER_UNSHIFTED_RO(15, 31, base_addr, raw);
#endif
  };

  Coherency_manager(Vm_mem *memmap)
  : _memmap(memmap), _gic_base(0), _cpc_base(0)
  {}

  static Region mem_region() { return Region::ss(Base_address, Cm_size); }

  void register_cpc(cxx::Ref_ptr<Vdev::Mips_cpc> const &cpc) { _cpc = cpc; }

  l4_umword_t read(unsigned reg, char, unsigned cpuid)
  {
    Dbg dbg(Dbg::Cpu, Dbg::Info, "CM");

    if (reg >= Core_local_base && reg < Core_local_base + Control_block_size)
      {
        if (!_cpc)
          return 0;

        return _cpc->cm_read_core(reg - Core_local_base, cpuid, false);
      }

    if (reg >= Core_other_base && reg < Core_other_base + Control_block_size)
      {
        if (!_cpc)
          return 0;

        return _cpc->cm_read_core(reg - Core_other_base, cpuid, true);
      }

    Dbg(Dbg::Cpu, Dbg::Trace, "CM").printf("reading GCR @ 0x%x\n", reg);
    switch (reg)
      {
      case Gcr_config:
        return _cpc->max_cpuid(); // no ICUs
      case Gcr_base:
        return Base_address;
      case Gcr_rev:
        return 8 << 8; // CM3
      case Gcr_gic_base:
        return _gic_base;
      case Gcr_cpc_base:
        return _cpc_base.raw;
      case Gcr_gic_status:
        return 1; // GIC is CM-controlled
      case Gcr_cpc_status:
        return 1; // CPC enabled
      case Gcr_sys_config2:
        return 1; // maximum 1 VP per core
      case Gcr_bev_base:
        return _cpc ? _cpc->bev_base() : 0;
      }

    Dbg(Dbg::Cpu, Dbg::Info, "CM").printf("reading @ 0x%x ignored.\n", reg);
    return 0;
  }

  void write(unsigned reg, char, l4_umword_t value, unsigned cpuid)
  {
    if (reg >= Core_local_base && reg < Core_local_base + Control_block_size)
      {
        if (_cpc)
          _cpc->cm_write_core(reg - Core_local_base, value, cpuid, false);
        return;
      }

    if (reg >= Core_other_base && reg < Core_other_base + Control_block_size)
      {
        if (_cpc)
          _cpc->cm_write_core(reg - Core_other_base, value, cpuid, true);
        return;
      }

    Dbg(Dbg::Cpu, Dbg::Trace, "CM")
      .printf("writing GCR 0x%lx @ 0x%x\n", value, reg);
    switch (reg)
      {
      case Gcr_gic_base:
        // XXX check that this address is expected
        _gic_base = value;
        break;
      case Gcr_cpc_base:
        {
          Cpc_base_addr_reg newbase(value);

          if (_cpc_base.base_addr())
            {
              _cpc_base.enable() = (unsigned)newbase.enable();

              if (newbase.enable()
                  && _cpc_base.base_addr() != newbase.base_addr())
                Dbg(Dbg::Cpu, Dbg::Warn, "CM")
                  .printf("WARNING: change of CPC base address ignored.\n");
            }
          else
            {
              _cpc_base.raw = newbase.raw;

              assert(_cpc);

              Dbg(Dbg::Cpu, Dbg::Info, "CM")
                .printf("Mapping CPC @ 0x%lx\n",
                        (l4_addr_t)_cpc_base.base_addr());

              (*_memmap)[Region::ss(_cpc_base.base_addr(),
                                    Mips_cpc::Cpc_size)] = _cpc;
            }
          break;
        }
      case Gcr_bev_base:
        if (_cpc)
          _cpc->set_bev_base(value);
        break;
      default:
        Dbg(Dbg::Cpu, Dbg::Info, "CM")
          .printf("writing GCR 0x%lx @ 0x%x ignored.\n", value, reg);
      }
  }

private:
  cxx::Ref_ptr<Vdev::Mips_cpc> _cpc;
  Vm_mem *_memmap;
  l4_addr_t _gic_base;
  Cpc_base_addr_reg _cpc_base;
};

} // name space
