/*
 * Copyright (C) 2017, 2019 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Alexander Warg <alexander.warg@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include "cpu_dev.h"
#include "guest_entry.h"

static const std::pair<l4_umword_t, const char *> MIPS_PROC_IDS[] =
  {{0x0001a700, "mips,m5150"},
   {0x0001a800, "mips,p5600"},
   {0x0001a900, "mips,i6400"},
   {0x0001b024, "mips,i6500"},
   {0, nullptr}};

static Dbg warn(Dbg::Cpu, Dbg::Warn, "CPU");
static Dbg info(Dbg::Cpu, Dbg::Info, "CPU");
static Dbg trace(Dbg::Cpu, Dbg::Trace, "CPU");

namespace Vmm
{

static l4_umword_t
get_proc_type(char const *compatible)
{
  if (!compatible)
    return Cpu_dev::Default_procid;

  for (auto *row = MIPS_PROC_IDS; row->second; ++row)
    if (strcmp(row->second, compatible) == 0)
      return row->first;

  return Cpu_dev::Default_procid;
}

Cpu_dev::Cpu_dev(unsigned idx, unsigned phys_id, Vdev::Dt_node const *node)
: Generic_cpu_dev(idx, phys_id), _status(0), _core_other(0)
{
  // If a compatible property exists, it may be used to specify
  // the reported CPU type (if supported by architecture). Without
  // compatible property, the default is used.
  char const *compatible = node ? node->get_prop<char>("compatible", nullptr)
                                : nullptr;
  _vcpu.set_proc_id(get_proc_type(compatible));
  _vcpu.alloc_fpu_state();
  _status.seq_state() = Seq_non_coherent;
}

void
Cpu_dev::reset()
{
  l4_umword_t sp;
  asm ("move %0, $sp" : "=r" (sp));

  _vcpu->saved_state = L4_VCPU_F_FPU_ENABLED
                       | L4_VCPU_F_USER_MODE
                       | L4_VCPU_F_IRQ
                       | L4_VCPU_F_PAGE_FAULTS
                       | L4_VCPU_F_EXCEPTIONS;
  _vcpu->entry_ip = (l4_umword_t)&c_vcpu_entry;
  _vcpu->entry_sp = sp & ~0xfUL;
  _vcpu->r.status |= 8;

  auto *s = _vcpu.state();
  // disable trapping of CF1&2, CG and GT, enable ctl2
  s->guest_ctl_0 |= 0x3000083;
  s->guest_ctl_0_ext |= 0x10; // CGI
  l4_umword_t cca = s->g_cfg[0] & 7UL;
  s->g_seg_ctl[0] = 0x00200010;
  s->g_seg_ctl[1] = 0x00000002 | (cca << 16);
  s->g_seg_ctl[2] = 0x04300030 | (cca << 16) | cca;
  s->g_ebase = (s->g_ebase & ~0x3ffUL) | _vcpu.get_vcpu_id();
  s->set_modified(L4_VM_MOD_GUEST_CTL_0
                  | L4_VM_MOD_GUEST_CTL_0_EXT
                  | L4_VM_MOD_CFG
                  | L4_VM_MOD_EBASE
                  | L4_VM_MOD_XLAT);

  Dbg(Dbg::Core, Dbg::Info)
    .printf("Starting vcpu %d @ 0x%lx (handler @ %lx with stack @ %lx)\n",
            _vcpu.get_vcpu_id(), _vcpu->r.ip, _vcpu->entry_ip, _vcpu->entry_sp);

  L4::Cap<L4::Thread> myself;
  auto e = l4_error(myself->vcpu_resume_commit(myself->vcpu_resume_start()));

  Err().printf("VMM exited with %ld\n", e);
}

void
Cpu_dev::start_vcpu(l4_addr_t bev_base)
{
  info.printf("Start of vcpu %d requested.\n", _vcpu.get_vcpu_id());

  // setup vcpu state
  if (_reset_base & 1)
    {
      _vcpu->r.ip = bev_base;
      trace.printf("Using BEV reset base 0x%lx\n", bev_base);
    }
  else
    {
      _vcpu->r.ip = _reset_base & Cm_loc_reset_base_addr_mask;
      trace.printf("Using Core reset base 0x%lx\n", _reset_base);
    }

  _vcpu.state()->g_status |= (1 << 2) | (1 << 22); // ERL, BEV

  reschedule();

  // consider it officially done
  // XXX should that be done in reset code?
  set_coherent();
}

void
Cpu_dev::stop_vcpu()
{
  warn.printf("Stop of vcpu %d requested. NOT IMPLEMENTED.\n",
              _vcpu.get_vcpu_id());
}

} // namespace
