/*
 * (c) 2013-2014 Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstdio>

#include <l4/re/error_helper>
#include <l4/re/rm>
#include <l4/re/util/cap_alloc>
#include <l4/sys/thread>
#include <l4/sys/vcpu.h>
#include <l4/re/util/br_manager>

#include "debug.h"
#include "vcpu_obj_registry.h"

namespace Vmm {

class Pt_walker;

class Generic_vcpu_ptr
{
public:
  l4_vcpu_state_t *operator -> () const noexcept
  { return _s; }

  l4_vcpu_state_t *operator * () const noexcept
  { return _s; }

  void control_ext(L4::Cap<L4::Thread> thread)
  {
    if (l4_error(thread->vcpu_control_ext(reinterpret_cast<l4_addr_t>(_s))))
      {
        Err().printf("FATAL: Could not create vCPU. "
                     "Running virtualization-enabled kernel?\n");
        L4Re::throw_error(-L4_ENODEV, "Enable extended vCPU mode.");
      }

    if (!l4_vcpu_check_version(_s))
      {
        Err().printf("FATAL: Could not create vCPU. "
                     "vCPU interface mismatch - Kernel %lx != User %x.\n",
                     _s->version, L4_VCPU_STATE_VERSION);
        L4Re::throw_error(-L4_ENODEV, "Matching vCPU interface versions.");
      }

    trace().printf("VCPU mapped @ %p and enabled\n", _s);
  }

  unsigned get_vcpu_id() const
  { return _s->user_data[Reg_vcpu_id]; }

  void set_vcpu_id(unsigned id)
  { _s->user_data[Reg_vcpu_id] = id; }

  Vcpu_obj_registry *get_ipc_registry() const
  { return reinterpret_cast<Vcpu_obj_registry *>(_s->user_data[Reg_ipc_registry]); }

  void set_ipc_registry(Vcpu_obj_registry *registry)
  { _s->user_data[Reg_ipc_registry] = reinterpret_cast<l4_umword_t>(registry); }

  L4Re::Util::Br_manager *get_bm() const
  { return reinterpret_cast<L4Re::Util::Br_manager *>(_s->user_data[Reg_bm]); }

  void set_bm(L4Re::Util::Br_manager *bm)
  { _s->user_data[Reg_bm] = reinterpret_cast<l4_umword_t>(bm); }

  Pt_walker *get_pt_walker() const
  { return reinterpret_cast<Pt_walker *>(_s->user_data[Reg_ptw_ptr]); }

  void set_pt_walker(Pt_walker *ptw)
  { _s->user_data[Reg_ptw_ptr] = reinterpret_cast<l4_umword_t>(ptw); }

  void handle_ipc(l4_msgtag_t tag, l4_umword_t label, l4_utcb_t *utcb)
  {
    // IPIs between CPUs have IRQs with zero label and are currently
    // not handled by the registery. Return immediately on these IPCs.
    if ((label & ~3UL) == 0)
      return;

    l4_msgtag_t r = l4_msgtag(-L4_ENOREPLY, 0, 0, 0);

    try
      {
        r = get_ipc_registry()->dispatch(tag, label, utcb);
      }
    catch (L4::Runtime_error &e)
      {
        warn().printf("Runtime exception in ipc path: %s(%ld)",
                      e.str(), e.err_no());
        r = l4_msgtag(e.err_no(), 0, 0, 0);
      }
    catch (int err)
      {
        warn().printf("Runtime exception in ipc path: %d",
                      err);
        r = l4_msgtag(err, 0, 0, 0);
      }
    catch (long err)
      {
        warn().printf("Runtime exception in ipc path: %ld",
                      err);
        r = l4_msgtag(err, 0, 0, 0);
      }

    if (r.label() != -L4_ENOREPLY)
      l4_ipc_send(L4_INVALID_CAP | L4_SYSF_REPLY, utcb, r,
                  L4_IPC_SEND_TIMEOUT_0);
  }

  void wait_for_ipc(l4_utcb_t *utcb, l4_timeout_t to)
  {
    l4_umword_t src;
    get_bm()->setup_wait(utcb, L4::Ipc_svr::Reply_separate);
    l4_msgtag_t tag = l4_ipc_wait(utcb, &src, to);
    if (!tag.has_error())
      handle_ipc(tag, src, utcb);
  }

  void process_pending_ipc(l4_utcb_t *utcb)
  {
    while (_s->sticky_flags & L4_VCPU_SF_IRQ_PENDING)
      wait_for_ipc(utcb, L4_IPC_BOTH_TIMEOUT_0);
  }

protected:
  enum User_data_regs
  {
    Reg_vcpu_id = 0,
    Reg_ipc_registry,
    Reg_bm,
    Reg_ptw_ptr,
    Reg_arch_base
  };

  static Dbg warn()
  { return Dbg(Dbg::Cpu, Dbg::Warn); }

  static Dbg info()
  { return Dbg(Dbg::Cpu, Dbg::Info); }

  static Dbg trace()
  { return Dbg(Dbg::Cpu, Dbg::Trace); }

  static_assert(Reg_arch_base <= 7, "Too many user_data registers used");

  explicit Generic_vcpu_ptr(l4_vcpu_state_t *s) : _s(s) {}

  static l4_umword_t reg_extend_width(l4_umword_t value, char size, bool signext)
  {
    if (signext)
      {
        switch (size)
          {
          case 0: return static_cast<l4_mword_t>(static_cast<l4_int8_t>(value));
          case 1: return static_cast<l4_mword_t>(static_cast<l4_int16_t>(value));
          case 2: return static_cast<l4_mword_t>(static_cast<l4_int32_t>(value));
          default: return value;
          }
      }

    switch (size)
      {
      case 0: return static_cast<l4_umword_t>(static_cast<l4_uint8_t>(value));
      case 1: return static_cast<l4_umword_t>(static_cast<l4_uint16_t>(value));
      case 2: return static_cast<l4_umword_t>(static_cast<l4_uint32_t>(value));
      default: return value;
      }
  }

  l4_vcpu_state_t *_s;
};

}
